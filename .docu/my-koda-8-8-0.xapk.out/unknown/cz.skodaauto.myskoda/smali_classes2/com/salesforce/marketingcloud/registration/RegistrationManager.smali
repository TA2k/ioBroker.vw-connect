.class public interface abstract Lcom/salesforce/marketingcloud/registration/RegistrationManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;,
        Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;
    }
.end annotation


# static fields
.field public static final a:Ljava/lang/String;

.field public static final b:Ljava/lang/String; = "Android"

.field public static final c:I = 0x80


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "RegistrationManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public abstract edit()Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract getAttributes()Ljava/util/Map;
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getContactKey()Ljava/lang/String;
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract getDeviceId()Ljava/lang/String;
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract getSignedString()Ljava/lang/String;
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract getSystemToken()Ljava/lang/String;
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract getTags()Ljava/util/Set;
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end method

.method public abstract registerForRegistrationEvents(Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract unregisterForRegistrationEvents(Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method
