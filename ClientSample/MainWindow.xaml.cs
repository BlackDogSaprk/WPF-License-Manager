/*
 * Copyright © 2014 Pasi J. Elo
 * Author:
 * Pasi J. Elo        blackdogspark@hotmail.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace ClientSample
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Windows;

    using Portable.Licensing;
    using Portable.Licensing.Validation;

    /// <summary>
    /// Interaction logic for MainWindow.
    /// </summary>
    public partial class MainWindow
    {
        /// <summary>
        /// The license object.
        /// </summary>
        private License ulicense;

        /// <summary>
        /// The public key.
        /// </summary>
        private string publicKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindow"/> class.
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// The license exception.
        /// </summary>
        /// <param name="license">
        /// The license.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        private static bool LicenseException(License license)
        {
            //// check licensetype.
            return license.Type == LicenseType.Trial;
        }

        /// <summary>
        /// The text box public key_ text changed.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void TextBoxPublicKeyTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            /*
                1. clear validation listbox.
                2. define a new stream and select and read the license.
                3. read the values from the license.
                4. validate the license (expiration date and signature).
             */
            TextBoxLicense.Text = string.Empty;

            var myStream = Stream.Null;

            try
            {
                var sr = new StreamReader(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\lic.lic");
                myStream = sr.BaseStream;
                if (myStream.Length <= 0)
                {
                    return;
                }

                this.ulicense = License.Load(myStream);

                this.Title = this.ulicense.AdditionalAttributes.Get("Sooftware") + " Licensed To '" + this.ulicense.Customer.Name + "'";

                this.publicKey = TextBoxPublicKey.Text;
                var str = this.ValidateLicense(this.ulicense);

                this.TextBoxLicense.Text = str;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Cannot read file from disk. Original error: " + ex.Message);
            }
            finally
            {
                //// Check this again, since we need to make sure we didn't throw an exception on open.
                if (myStream != null)
                {
                    myStream.Close();
                }
            }
        }

        /// <summary>
        /// The validate license.
        /// </summary>
        /// <param name="license">
        /// The license.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        private string ValidateLicense(License license)
        {
            //// validate license and define return value.
            const string ReturnValue = "License is Valid";

            var validationFailures =
                license.Validate()
                    .ExpirationDate()
                    .When(LicenseException)
                    .And()
                    .Signature(this.publicKey)
                    .AssertValidLicense();

            var failures = validationFailures as IValidationFailure[] ?? validationFailures.ToArray();

            return !failures.Any() ? ReturnValue : failures.Aggregate(string.Empty, (current, validationFailure) => current + validationFailure.HowToResolve + ": " + "\r\n" + validationFailure.Message + "\r\n");
        }
    }
}
