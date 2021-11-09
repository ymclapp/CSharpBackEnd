using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace E_Commerce.Models
{
    public class Product
    {
        public int Id { get; set; }

        [Display(Name = "Product Name")]
        [Required]
        [StringLength(200)]
        public string Name { get; set; }
        public int Price { get; set; }
        public int InventoryAmount { get; set; }
        public string Summary { get; set; }
        public string Condition { get; set; }

        //If you leave this out, it will probably figure out that you need one - automatically makes it required
        [Display(Name = "Product Category")]
        public int ProductCategoryId { get; set; }

        //Navigation Property that makes a ProductCategoryId a Foreign Key
        public ProductCategory ProductCategory { get; set; }

    }
}
