import jwt from 'jsonwebtoken'

type Environment = 'sandbox' | 'production'

interface PaymentInfo {
  /**
   * Payment amount (up to 2 decimal places).
   */
  amount: number

  /**
   * Payment currency. Currently only EUR is supported.
   */
  currency: 'EUR'

  /**
   * The merchant's name to be displayed in Montonio's interface 
   * if it differs from the one set in the Partner System.
   */
  merchant_name?: string

  /**
   * The order reference in the merchant's system (e.g. the order ID).
   */
  merchant_reference: string

  /**
   * The URL where the customer will be redirected back to after completing or cancelling a payment.
   * Once the customer completes the payment, they will be redirected back to the this URL 
   * with a new `payment_token` appended to it as a query parameter
   */
  merchant_return_url: string

  /**
   * The URL to send a webhook notification when a payment is completed.
   * Once the customer completes the payment, Montonio will send a `POST` request to this URL 
   * with a new `payment_token` appended to it as a query parameter.
   */
  merchant_notification_url?: string

  /**
   * Description of the payment that will be relayed to the bank's payment order. 
   * If left blank, it will default to the value of merchant_reference.
   */
  payment_information_unstructured?: string

  /**
   * Structured payment reference number. 
   * This is a standardised reference number used for accounting purposes and will be validated by banks.
   * Leave blank if you do not use reference numbers to link payments.
   */
  payment_information_structured?: string

  /**
   * The bank that the customer chose for this payment 
   * if you allow them to select their bank of choice in your checkout.
   * Leave this blank to let the customer choose their bank in our interface.
   */
  preselected_aspsp?: string

  /**
   * The preferred language of the payment gateway. Defaults to the merchant country's official language.
   * Available values are en_US, et, lt, ru.
   */
  preselected_locale?: 'en_US' | 'et' | 'lt' | 'ru'

  /**
   * The customer's e-mail address. 
   * Use this to identify customers more easily in Montonio's Partner System.
   */
  checkout_email?: string

  /**
   * The customer's phone number.
   * Use this to identify customers more easily in Montonio's Partner System.
   */
  checkout_phone_number?: string

  /**
   * The customer's first name.
   * Use this to identify customers more easily in Montonio's Partner System.
   */
  checkout_first_name?: string

  /**
   * The customer's last name.
   * Use this to identify customers more easily in Montonio's Partner System.
   */
  checkout_last_name?: string
}

/**
 * Get JWT token with payment information
 *
 * @returns JWT token
 */
export const getPaymentToken = ({
  payment,
  accessKey,
  secretKey,
}: {
  payment: PaymentInfo
  accessKey: string
  secretKey: string
}): string =>
  jwt.sign(
    {
      ...payment,
      access_key: accessKey,
    },
    secretKey,
    {
      // The JWT is signed with your Secret Key using HMAC SHA256 (HS256).
      algorithm: 'HS256',
      expiresIn: '10m',
    },
  )


/**
 * Get payment URL with embedded payment token
 *
 * @returns payment URL
 */
export const getPaymentUrl = (paymentToken: string, env: Environment = 'sandbox'): string =>
  `https://${
    env === 'sandbox' ? 'sandbox-' : ''
  }payments.montonio.com?payment_token=${paymentToken}`

const hasOwnProperty = <X extends object, Y extends PropertyKey>(
  obj: X,
  prop: Y,
): obj is X & Record<Y, unknown> => obj.hasOwnProperty(prop)

/**
 * Get reference from the payment token
 *
 * @returns If payment was successful it returns reference from the token, otherwise it returns null
 */
export const getReferenceFromPaymentToken = (
  paymentToken: string,
  secretKey: string,
): string | null => {
  const decoded = jwt.verify(paymentToken, secretKey)

  if (typeof decoded !== 'object' || decoded === null) return null

  if (!hasOwnProperty(decoded, 'status')) return null

  if (decoded.status !== 'finalized') return null

  if (!hasOwnProperty(decoded, 'merchant_reference')) return null

  if (typeof decoded.merchant_reference !== 'string') return null

  return decoded.merchant_reference
}


/**
 * Get bank list URL
 *
 * @returns If payment was successful it returns reference from the token, otherwise it returns null
 */
export const getBankListUrl = ({
  accessKey,
  secretKey,
  env = 'sandbox',
}: {
  accessKey: string
  secretKey: string
  env: Environment
}) => {
  const auth = jwt.sign(
    {
      access_key: accessKey,
    },
    secretKey,
    {
      algorithm: 'HS256',
      expiresIn: '1h',
    },
  )

  return {
    url: `https://api.${
      env === 'sandbox' ? 'sandbox-' : ''
    }payments.montonio.com/pis/v2/merchants/aspsps`,
    auth,
  }
}
