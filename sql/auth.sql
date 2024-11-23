-- Drop existing objects
DROP FUNCTION IF EXISTS public.authenticate CASCADE;
DROP TYPE IF EXISTS public.authenticate_input CASCADE;
DROP TYPE IF EXISTS public.authenticate_input_record CASCADE;
DROP TYPE IF EXISTS public.auth_result CASCADE;

-- Create input types
CREATE TYPE public.authenticate_input_record AS (
    email text,
    password text
);

CREATE TYPE public.authenticate_input AS (
    input public.authenticate_input_record
);

-- Create result type
CREATE TYPE public.auth_result AS (
    auth_result json,
    client_mutation_id text
);

-- Function to generate JWT token
CREATE OR REPLACE FUNCTION public.generate_jwt(user_id integer, user_role text DEFAULT 'user')
RETURNS text AS $$
BEGIN
    RETURN jwt.sign(
        json_build_object(
            'role', user_role,
            'user_id', user_id,
            'exp', extract(epoch from now() + interval '24 hours')::integer
        ),
        current_setting('app.jwt_secret')
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
    user_data json;
    jwt_token text;
BEGIN
    SELECT 
        CASE 
            WHEN uc.password_hash = crypt((auth).input.password, uc.password_hash) THEN
                json_build_object(
                    'id', ud.id,
                    'userName', ud.user_name,
                    'dateOfBirth', ud.date_of_birth,
                    'gender', ud.gender,
                    'isVerifiedFlag', ud.is_verified_flag,
                    'jwtToken', generate_jwt(ud.id)  -- Add JWT token to the response
                )
            ELSE NULL
        END INTO user_data
    FROM contact_details cd
    JOIN user_credentials uc ON uc.user_id = cd.user_id
    JOIN user_details ud ON ud.id = cd.user_id
    WHERE cd.email = (auth).input.email
    LIMIT 1;

    IF user_data IS NULL THEN
        RAISE EXCEPTION 'Invalid email or password';
    END IF;

    RETURN ROW(user_data, NULL::text)::public.auth_result;
END;
$$;

-- Create JWT schema and required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS jwt;

CREATE OR REPLACE FUNCTION jwt.sign(payload json, secret text, algorithm text DEFAULT 'HS256')
RETURNS text LANGUAGE sql AS $$
WITH
  header AS (
    SELECT pgcrypto.encode(
      '{"alg":"' || algorithm || '","typ":"JWT"}',
      'base64'
    ) as data
  ),
  payload_encoded AS (
    SELECT pgcrypto.encode(
      payload::text,
      'base64'
    ) as data
  ),
  signdata AS (
    SELECT header.data || '.' || payload_encoded.data as data
    FROM header, payload_encoded
  )
SELECT
  signdata.data || '.' ||
  pgcrypto.encode(
    pgcrypto.hmac(
      signdata.data,
      secret,
      CASE algorithm
        WHEN 'HS256' THEN 'sha256'
        WHEN 'HS384' THEN 'sha384'
        WHEN 'HS512' THEN 'sha512'
        ELSE '' END
    ),
    'base64'
  )
FROM signdata;
$$;

-- Set JWT secret from environment variable
DO $$ 
BEGIN 
    PERFORM set_config('app.jwt_secret', current_setting('jwt_secret'), false);
EXCEPTION 
    WHEN undefined_object THEN 
        RAISE EXCEPTION 'JWT_SECRET environment variable is not set in PostGraphile configuration';
END $$;

-- Grant permissions
GRANT EXECUTE ON FUNCTION public.authenticate(public.authenticate_input) TO postgraphile;
GRANT EXECUTE ON FUNCTION public.generate_jwt(integer, text) TO postgraphile;
GRANT EXECUTE ON FUNCTION jwt.sign(json, text, text) TO postgraphile;
GRANT SELECT ON TABLE public.contact_details TO postgraphile;
GRANT SELECT ON TABLE public.user_credentials TO postgraphile;
GRANT SELECT ON TABLE public.user_details TO postgraphile;
GRANT USAGE ON SCHEMA jwt TO postgraphile;

COMMIT;