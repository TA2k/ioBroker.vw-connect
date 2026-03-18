.class public interface abstract Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/registration/RegistrationManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x609
    name = "Editor"
.end annotation


# virtual methods
.method public abstract addTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method

.method public abstract addTags(Ljava/lang/Iterable;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;"
        }
    .end annotation
.end method

.method public varargs abstract addTags([Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method

.method public abstract clearAttribute(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method

.method public abstract clearAttributes(Ljava/lang/Iterable;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;"
        }
    .end annotation
.end method

.method public varargs abstract clearAttributes([Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method

.method public abstract clearTags()Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method

.method public abstract commit()Z
.end method

.method public abstract removeTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method

.method public abstract removeTags(Ljava/lang/Iterable;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;"
        }
    .end annotation
.end method

.method public varargs abstract removeTags([Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method

.method public abstract setAttribute(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method

.method public abstract setContactKey(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method

.method public abstract setSignedString(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.end method
