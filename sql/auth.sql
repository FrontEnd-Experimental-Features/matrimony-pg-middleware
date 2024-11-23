-- Drop existing objects
DROP FUNCTION IF EXISTS public.authenticate CASCADE;
DROP TYPE IF EXISTS public.authenticate_input CASCADE;
DROP TYPE IF EXISTS public.authenticate_input_record CASCADE;
DROP TYPE IF EXISTS public.auth_result CASCADE;

-- Create extensions first
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create roles if they don't exist
DO $$ 
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'matrimony_user') THEN
    CREATE ROLE matrimony_user;
  END IF;
END
$$;

-- Create input types
CREATE TYPE public.authenticate_input_record AS (
    email text,
    password text
);
COMMENT ON TYPE public.authenticate_input_record IS E'@name LoginCredentials';

CREATE TYPE public.authenticate_input AS (
    input public.authenticate_input_record
);
COMMENT ON TYPE public.authenticate_input IS E'@name LoginInput';

-- Create result type
CREATE TYPE public.auth_result AS (
    auth_result json,
    client_mutation_id text
);
COMMENT ON TYPE public.auth_result IS E'@name LoginPayload';

-- Create JWT schema
CREATE SCHEMA IF NOT EXISTS jwt;

-- Function to base64url encode
CREATE OR REPLACE FUNCTION jwt.url_encode(data bytea) RETURNS text LANGUAGE sql AS $$
    SELECT TRANSLATE(encode(data, 'base64'), E'+/=\n', '-_');
$$;

-- Create JWT signing function
CREATE OR REPLACE FUNCTION jwt.sign(payload json, secret text, algorithm text DEFAULT 'HS256')
RETURNS text LANGUAGE sql AS $$
WITH
  header AS (
    SELECT jwt.url_encode(convert_to('{"alg":"' || algorithm || '","typ":"JWT"}', 'utf8')) as data
  ),
  payload_encoded AS (
    SELECT jwt.url_encode(convert_to(payload::text, 'utf8')) as data
  ),
  signdata AS (
    SELECT header.data || '.' || payload_encoded.data as data
    FROM header, payload_encoded
  )
SELECT
  signdata.data || '.' ||
  jwt.url_encode(
    hmac(
      signdata.data::bytea,
      secret::bytea,
      CASE algorithm
        WHEN 'HS256' THEN 'sha256'
        WHEN 'HS384' THEN 'sha384'
        WHEN 'HS512' THEN 'sha512'
        ELSE '' END
    )
  )
FROM signdata;
$$;

-- Create configuration table
CREATE TABLE IF NOT EXISTS public.config (
    key text PRIMARY KEY,
    value text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);

-- Insert placeholder for JWT secret (actual secret will be set by the application)
INSERT INTO public.config (key, value) 
VALUES ('jwt.secret', 'PLACEHOLDER_JWT_SECRET_TO_BE_SET_BY_APP') 
ON CONFLICT (key) DO NOTHING;

-- Function to generate JWT token
CREATE OR REPLACE FUNCTION public.generate_jwt(user_id integer)
RETURNS text AS $$
DECLARE
    jwt_secret text;
BEGIN
    -- Get JWT secret from config table
    SELECT value INTO jwt_secret FROM public.config WHERE key = 'jwt.secret';
    
    IF jwt_secret IS NULL OR jwt_secret = 'PLACEHOLDER_JWT_SECRET_TO_BE_SET_BY_APP' THEN
        RAISE EXCEPTION 'JWT secret has not been initialized by the application';
    END IF;

    RETURN jwt.sign(
        json_build_object(
            'role', 'matrimony_user',
            'user_id', user_id,
            'exp', extract(epoch from now() + interval '24 hours')::integer
        ),
        jwt_secret
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Create authentication function
CREATE OR REPLACE FUNCTION public.authenticate(
    auth public.authenticate_input
)
    RETURNS public.auth_result
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
AS $$
DECLARE
    user_details json;
    jwt_token text;
BEGIN
    -- First get the JWT token
    SELECT generate_jwt(ud.id) INTO jwt_token
    FROM contact_details cd
    JOIN user_credentials uc ON uc.user_id = cd.user_id
    JOIN user_details ud ON ud.id = cd.user_id
    WHERE cd.email = (auth).input.email
    AND uc.password_hash = crypt((auth).input.password, uc.password_hash)
    LIMIT 1;

    -- Then get user details
    SELECT 
        CASE 
            WHEN uc.password_hash = crypt((auth).input.password, uc.password_hash) THEN
                json_build_object(
                    'userDetails', json_build_object(
                        'id', ud.id,
                        'userName', ud.user_name,
                        'dateOfBirth', ud.date_of_birth,
                        'gender', ud.gender,
                        'isVerifiedFlag', ud.is_verified_flag,
                        'jwtToken', jwt_token
                    )
                )
            ELSE NULL
        END INTO user_details
    FROM contact_details cd
    JOIN user_credentials uc ON uc.user_id = cd.user_id
    JOIN user_details ud ON ud.id = cd.user_id
    WHERE cd.email = (auth).input.email
    LIMIT 1;

    IF user_details IS NULL THEN
        RAISE EXCEPTION 'Invalid email or password';
    END IF;

    RETURN ROW(user_details, NULL::text)::public.auth_result;
END;
$$;

-- Grant permissions
GRANT USAGE ON SCHEMA public TO matrimony_user;
GRANT EXECUTE ON FUNCTION public.authenticate(public.authenticate_input) TO matrimony_user;
GRANT EXECUTE ON FUNCTION public.generate_jwt(integer) TO matrimony_user;
GRANT EXECUTE ON FUNCTION jwt.sign(json, text, text) TO matrimony_user;
GRANT EXECUTE ON FUNCTION jwt.url_encode(bytea) TO matrimony_user;
GRANT SELECT ON TABLE public.contact_details TO matrimony_user;
GRANT SELECT ON TABLE public.user_credentials TO matrimony_user;
GRANT SELECT ON TABLE public.user_details TO matrimony_user;
GRANT SELECT ON TABLE public.config TO matrimony_user;
GRANT USAGE ON SCHEMA jwt TO matrimony_user;

COMMIT;