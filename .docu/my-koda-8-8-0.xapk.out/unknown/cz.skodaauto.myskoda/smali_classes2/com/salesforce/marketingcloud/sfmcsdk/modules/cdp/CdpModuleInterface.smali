.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleInterface;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008&\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J!\u0010\t\u001a\u00020\u00082\u0008\u0010\u0005\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0007\u001a\u00020\u0006H&\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0019\u0010\r\u001a\u00020\u00082\u0008\u0010\u000c\u001a\u0004\u0018\u00010\u000bH&\u00a2\u0006\u0004\u0008\r\u0010\u000eR\u001c\u0010\u0014\u001a\u00020\u000f8&@&X\u00a6\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\u0010\u0010\u0011\"\u0004\u0008\u0012\u0010\u0013\u00a8\u0006\u0015"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleInterface;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;",
        "<init>",
        "()V",
        "Lcom/salesforce/marketingcloud/cdp/location/Coordinates;",
        "coordinates",
        "",
        "expiresIn",
        "Llx0/b0;",
        "setLocation",
        "(Lcom/salesforce/marketingcloud/cdp/location/Coordinates;J)V",
        "Lcom/salesforce/marketingcloud/cdp/events/Event;",
        "event",
        "track",
        "(Lcom/salesforce/marketingcloud/cdp/events/Event;)V",
        "Lcom/salesforce/marketingcloud/cdp/consent/Consent;",
        "getConsent",
        "()Lcom/salesforce/marketingcloud/cdp/consent/Consent;",
        "setConsent",
        "(Lcom/salesforce/marketingcloud/cdp/consent/Consent;)V",
        "consent",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public abstract getConsent()Lcom/salesforce/marketingcloud/cdp/consent/Consent;
.end method

.method public abstract setConsent(Lcom/salesforce/marketingcloud/cdp/consent/Consent;)V
.end method

.method public abstract setLocation(Lcom/salesforce/marketingcloud/cdp/location/Coordinates;J)V
.end method

.method public abstract track(Lcom/salesforce/marketingcloud/cdp/events/Event;)V
.end method
