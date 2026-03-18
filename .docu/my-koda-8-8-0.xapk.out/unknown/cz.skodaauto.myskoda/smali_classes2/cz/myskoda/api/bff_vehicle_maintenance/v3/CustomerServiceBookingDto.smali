.class public final Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0008\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008:\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u00bf\u0001\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0007\u0012\u0008\u0008\u0001\u0010\u0008\u001a\u00020\u0007\u0012\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\n\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u000c\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u000e\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u000f\u001a\u0004\u0018\u00010\u0010\u0012\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u0007\u0012\u0010\u0008\u0003\u0010\u0012\u001a\n\u0012\u0004\u0012\u00020\u0014\u0018\u00010\u0013\u0012\n\u0008\u0003\u0010\u0015\u001a\u0004\u0018\u00010\u0016\u0012\u0010\u0008\u0003\u0010\u0017\u001a\n\u0012\u0004\u0012\u00020\u0018\u0018\u00010\u0013\u00a2\u0006\u0004\u0008\u0019\u0010\u001aJ\t\u0010A\u001a\u00020\u0003H\u00c6\u0003J\t\u0010B\u001a\u00020\u0005H\u00c6\u0003J\t\u0010C\u001a\u00020\u0007H\u00c6\u0003J\t\u0010D\u001a\u00020\u0007H\u00c6\u0003J\u000b\u0010E\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010F\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010G\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010H\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010I\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010J\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u0010\u0010K\u001a\u0004\u0018\u00010\u0010H\u00c6\u0003\u00a2\u0006\u0002\u00105J\u000b\u0010L\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003J\u0011\u0010M\u001a\n\u0012\u0004\u0012\u00020\u0014\u0018\u00010\u0013H\u00c6\u0003J\u000b\u0010N\u001a\u0004\u0018\u00010\u0016H\u00c6\u0003J\u0011\u0010O\u001a\n\u0012\u0004\u0012\u00020\u0018\u0018\u00010\u0013H\u00c6\u0003J\u00c6\u0001\u0010P\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0003\u0010\u0008\u001a\u00020\u00072\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\n\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u000c\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u000e\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u000f\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u00072\u0010\u0008\u0003\u0010\u0012\u001a\n\u0012\u0004\u0012\u00020\u0014\u0018\u00010\u00132\n\u0008\u0003\u0010\u0015\u001a\u0004\u0018\u00010\u00162\u0010\u0008\u0003\u0010\u0017\u001a\n\u0012\u0004\u0012\u00020\u0018\u0018\u00010\u0013H\u00c6\u0001\u00a2\u0006\u0002\u0010QJ\u0013\u0010R\u001a\u00020S2\u0008\u0010T\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010U\u001a\u00020\u0010H\u00d6\u0001J\t\u0010V\u001a\u00020\u0007H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001b\u0010\u001c\u001a\u0004\u0008\u001d\u0010\u001eR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001f\u0010\u001c\u001a\u0004\u0008 \u0010!R\u001c\u0010\u0006\u001a\u00020\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\"\u0010\u001c\u001a\u0004\u0008#\u0010$R\u001c\u0010\u0008\u001a\u00020\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008%\u0010\u001c\u001a\u0004\u0008&\u0010$R\u001e\u0010\t\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\'\u0010\u001c\u001a\u0004\u0008(\u0010\u001eR\u001e\u0010\n\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008)\u0010\u001c\u001a\u0004\u0008*\u0010\u001eR\u001e\u0010\u000b\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008+\u0010\u001c\u001a\u0004\u0008,\u0010\u001eR\u001e\u0010\u000c\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008-\u0010\u001c\u001a\u0004\u0008.\u0010\u001eR\u001e\u0010\r\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008/\u0010\u001c\u001a\u0004\u00080\u0010\u001eR\u001e\u0010\u000e\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u00081\u0010\u001c\u001a\u0004\u00082\u0010\u001eR \u0010\u000f\u001a\u0004\u0018\u00010\u00108\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u00106\u0012\u0004\u00083\u0010\u001c\u001a\u0004\u00084\u00105R\u001e\u0010\u0011\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u00087\u0010\u001c\u001a\u0004\u00088\u0010$R$\u0010\u0012\u001a\n\u0012\u0004\u0012\u00020\u0014\u0018\u00010\u00138\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u00089\u0010\u001c\u001a\u0004\u0008:\u0010;R\u001e\u0010\u0015\u001a\u0004\u0018\u00010\u00168\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008<\u0010\u001c\u001a\u0004\u0008=\u0010>R$\u0010\u0017\u001a\n\u0012\u0004\u0012\u00020\u0018\u0018\u00010\u00138\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008?\u0010\u001c\u001a\u0004\u0008@\u0010;\u00a8\u0006W"
    }
    d2 = {
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;",
        "",
        "creationDate",
        "Ljava/time/OffsetDateTime;",
        "servicePartner",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;",
        "bookingId",
        "",
        "resolution",
        "acceptedDate",
        "confirmationDate",
        "closedDate",
        "appointmentDate",
        "contactedDate",
        "updateDate",
        "mileageInKm",
        "",
        "type",
        "extras",
        "",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;",
        "addOns",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;",
        "warnings",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;",
        "<init>",
        "(Ljava/time/OffsetDateTime;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;)V",
        "getCreationDate$annotations",
        "()V",
        "getCreationDate",
        "()Ljava/time/OffsetDateTime;",
        "getServicePartner$annotations",
        "getServicePartner",
        "()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;",
        "getBookingId$annotations",
        "getBookingId",
        "()Ljava/lang/String;",
        "getResolution$annotations",
        "getResolution",
        "getAcceptedDate$annotations",
        "getAcceptedDate",
        "getConfirmationDate$annotations",
        "getConfirmationDate",
        "getClosedDate$annotations",
        "getClosedDate",
        "getAppointmentDate$annotations",
        "getAppointmentDate",
        "getContactedDate$annotations",
        "getContactedDate",
        "getUpdateDate$annotations",
        "getUpdateDate",
        "getMileageInKm$annotations",
        "getMileageInKm",
        "()Ljava/lang/Integer;",
        "Ljava/lang/Integer;",
        "getType$annotations",
        "getType",
        "getExtras$annotations",
        "getExtras",
        "()Ljava/util/List;",
        "getAddOns$annotations",
        "getAddOns",
        "()Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;",
        "getWarnings$annotations",
        "getWarnings",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "component7",
        "component8",
        "component9",
        "component10",
        "component11",
        "component12",
        "component13",
        "component14",
        "component15",
        "copy",
        "(Ljava/time/OffsetDateTime;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;",
        "equals",
        "",
        "other",
        "hashCode",
        "toString",
        "bff-api_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final acceptedDate:Ljava/time/OffsetDateTime;

.field private final addOns:Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

.field private final appointmentDate:Ljava/time/OffsetDateTime;

.field private final bookingId:Ljava/lang/String;

.field private final closedDate:Ljava/time/OffsetDateTime;

.field private final confirmationDate:Ljava/time/OffsetDateTime;

.field private final contactedDate:Ljava/time/OffsetDateTime;

.field private final creationDate:Ljava/time/OffsetDateTime;

.field private final extras:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;",
            ">;"
        }
    .end annotation
.end field

.field private final mileageInKm:Ljava/lang/Integer;

.field private final resolution:Ljava/lang/String;

.field private final servicePartner:Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

.field private final type:Ljava/lang/String;

.field private final updateDate:Ljava/time/OffsetDateTime;

.field private final warnings:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/time/OffsetDateTime;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;)V
    .locals 1
    .param p1    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "creationDate"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "servicePartner"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "bookingId"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "resolution"
        .end annotation
    .end param
    .param p5    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "acceptedDate"
        .end annotation
    .end param
    .param p6    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "confirmationDate"
        .end annotation
    .end param
    .param p7    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "closedDate"
        .end annotation
    .end param
    .param p8    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "appointmentDate"
        .end annotation
    .end param
    .param p9    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "contactedDate"
        .end annotation
    .end param
    .param p10    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "updateDate"
        .end annotation
    .end param
    .param p11    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "mileageInKm"
        .end annotation
    .end param
    .param p12    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "type"
        .end annotation
    .end param
    .param p13    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "extras"
        .end annotation
    .end param
    .param p14    # Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "addOns"
        .end annotation
    .end param
    .param p15    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "warnings"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/time/OffsetDateTime;",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/lang/Integer;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;",
            ">;",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;",
            ">;)V"
        }
    .end annotation

    const-string v0, "creationDate"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "servicePartner"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bookingId"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "resolution"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->creationDate:Ljava/time/OffsetDateTime;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->servicePartner:Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->bookingId:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->resolution:Ljava/lang/String;

    .line 6
    iput-object p5, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->acceptedDate:Ljava/time/OffsetDateTime;

    .line 7
    iput-object p6, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->confirmationDate:Ljava/time/OffsetDateTime;

    .line 8
    iput-object p7, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->closedDate:Ljava/time/OffsetDateTime;

    .line 9
    iput-object p8, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->appointmentDate:Ljava/time/OffsetDateTime;

    .line 10
    iput-object p9, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->contactedDate:Ljava/time/OffsetDateTime;

    .line 11
    iput-object p10, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->updateDate:Ljava/time/OffsetDateTime;

    .line 12
    iput-object p11, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->mileageInKm:Ljava/lang/Integer;

    .line 13
    iput-object p12, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->type:Ljava/lang/String;

    .line 14
    iput-object p13, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->extras:Ljava/util/List;

    .line 15
    iput-object p14, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->addOns:Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    move-object/from16 p1, p15

    .line 16
    iput-object p1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->warnings:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/time/OffsetDateTime;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;ILkotlin/jvm/internal/g;)V
    .locals 19

    move/from16 v0, p16

    and-int/lit8 v1, v0, 0x10

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    move-object v8, v2

    goto :goto_0

    :cond_0
    move-object/from16 v8, p5

    :goto_0
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_1

    move-object v9, v2

    goto :goto_1

    :cond_1
    move-object/from16 v9, p6

    :goto_1
    and-int/lit8 v1, v0, 0x40

    if-eqz v1, :cond_2

    move-object v10, v2

    goto :goto_2

    :cond_2
    move-object/from16 v10, p7

    :goto_2
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_3

    move-object v11, v2

    goto :goto_3

    :cond_3
    move-object/from16 v11, p8

    :goto_3
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_4

    move-object v12, v2

    goto :goto_4

    :cond_4
    move-object/from16 v12, p9

    :goto_4
    and-int/lit16 v1, v0, 0x200

    if-eqz v1, :cond_5

    move-object v13, v2

    goto :goto_5

    :cond_5
    move-object/from16 v13, p10

    :goto_5
    and-int/lit16 v1, v0, 0x400

    if-eqz v1, :cond_6

    move-object v14, v2

    goto :goto_6

    :cond_6
    move-object/from16 v14, p11

    :goto_6
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_7

    move-object v15, v2

    goto :goto_7

    :cond_7
    move-object/from16 v15, p12

    :goto_7
    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_8

    move-object/from16 v16, v2

    goto :goto_8

    :cond_8
    move-object/from16 v16, p13

    :goto_8
    and-int/lit16 v1, v0, 0x2000

    if-eqz v1, :cond_9

    move-object/from16 v17, v2

    goto :goto_9

    :cond_9
    move-object/from16 v17, p14

    :goto_9
    and-int/lit16 v0, v0, 0x4000

    if-eqz v0, :cond_a

    move-object/from16 v18, v2

    :goto_a
    move-object/from16 v3, p0

    move-object/from16 v4, p1

    move-object/from16 v5, p2

    move-object/from16 v6, p3

    move-object/from16 v7, p4

    goto :goto_b

    :cond_a
    move-object/from16 v18, p15

    goto :goto_a

    .line 17
    :goto_b
    invoke-direct/range {v3 .. v18}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;-><init>(Ljava/time/OffsetDateTime;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;Ljava/time/OffsetDateTime;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;ILjava/lang/Object;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p16

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-object v2, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->creationDate:Ljava/time/OffsetDateTime;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move-object/from16 v2, p1

    .line 13
    .line 14
    :goto_0
    and-int/lit8 v3, v1, 0x2

    .line 15
    .line 16
    if-eqz v3, :cond_1

    .line 17
    .line 18
    iget-object v3, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->servicePartner:Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-object/from16 v3, p2

    .line 22
    .line 23
    :goto_1
    and-int/lit8 v4, v1, 0x4

    .line 24
    .line 25
    if-eqz v4, :cond_2

    .line 26
    .line 27
    iget-object v4, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->bookingId:Ljava/lang/String;

    .line 28
    .line 29
    goto :goto_2

    .line 30
    :cond_2
    move-object/from16 v4, p3

    .line 31
    .line 32
    :goto_2
    and-int/lit8 v5, v1, 0x8

    .line 33
    .line 34
    if-eqz v5, :cond_3

    .line 35
    .line 36
    iget-object v5, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->resolution:Ljava/lang/String;

    .line 37
    .line 38
    goto :goto_3

    .line 39
    :cond_3
    move-object/from16 v5, p4

    .line 40
    .line 41
    :goto_3
    and-int/lit8 v6, v1, 0x10

    .line 42
    .line 43
    if-eqz v6, :cond_4

    .line 44
    .line 45
    iget-object v6, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->acceptedDate:Ljava/time/OffsetDateTime;

    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_4
    move-object/from16 v6, p5

    .line 49
    .line 50
    :goto_4
    and-int/lit8 v7, v1, 0x20

    .line 51
    .line 52
    if-eqz v7, :cond_5

    .line 53
    .line 54
    iget-object v7, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->confirmationDate:Ljava/time/OffsetDateTime;

    .line 55
    .line 56
    goto :goto_5

    .line 57
    :cond_5
    move-object/from16 v7, p6

    .line 58
    .line 59
    :goto_5
    and-int/lit8 v8, v1, 0x40

    .line 60
    .line 61
    if-eqz v8, :cond_6

    .line 62
    .line 63
    iget-object v8, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->closedDate:Ljava/time/OffsetDateTime;

    .line 64
    .line 65
    goto :goto_6

    .line 66
    :cond_6
    move-object/from16 v8, p7

    .line 67
    .line 68
    :goto_6
    and-int/lit16 v9, v1, 0x80

    .line 69
    .line 70
    if-eqz v9, :cond_7

    .line 71
    .line 72
    iget-object v9, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->appointmentDate:Ljava/time/OffsetDateTime;

    .line 73
    .line 74
    goto :goto_7

    .line 75
    :cond_7
    move-object/from16 v9, p8

    .line 76
    .line 77
    :goto_7
    and-int/lit16 v10, v1, 0x100

    .line 78
    .line 79
    if-eqz v10, :cond_8

    .line 80
    .line 81
    iget-object v10, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->contactedDate:Ljava/time/OffsetDateTime;

    .line 82
    .line 83
    goto :goto_8

    .line 84
    :cond_8
    move-object/from16 v10, p9

    .line 85
    .line 86
    :goto_8
    and-int/lit16 v11, v1, 0x200

    .line 87
    .line 88
    if-eqz v11, :cond_9

    .line 89
    .line 90
    iget-object v11, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->updateDate:Ljava/time/OffsetDateTime;

    .line 91
    .line 92
    goto :goto_9

    .line 93
    :cond_9
    move-object/from16 v11, p10

    .line 94
    .line 95
    :goto_9
    and-int/lit16 v12, v1, 0x400

    .line 96
    .line 97
    if-eqz v12, :cond_a

    .line 98
    .line 99
    iget-object v12, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->mileageInKm:Ljava/lang/Integer;

    .line 100
    .line 101
    goto :goto_a

    .line 102
    :cond_a
    move-object/from16 v12, p11

    .line 103
    .line 104
    :goto_a
    and-int/lit16 v13, v1, 0x800

    .line 105
    .line 106
    if-eqz v13, :cond_b

    .line 107
    .line 108
    iget-object v13, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->type:Ljava/lang/String;

    .line 109
    .line 110
    goto :goto_b

    .line 111
    :cond_b
    move-object/from16 v13, p12

    .line 112
    .line 113
    :goto_b
    and-int/lit16 v14, v1, 0x1000

    .line 114
    .line 115
    if-eqz v14, :cond_c

    .line 116
    .line 117
    iget-object v14, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->extras:Ljava/util/List;

    .line 118
    .line 119
    goto :goto_c

    .line 120
    :cond_c
    move-object/from16 v14, p13

    .line 121
    .line 122
    :goto_c
    and-int/lit16 v15, v1, 0x2000

    .line 123
    .line 124
    if-eqz v15, :cond_d

    .line 125
    .line 126
    iget-object v15, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->addOns:Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    .line 127
    .line 128
    goto :goto_d

    .line 129
    :cond_d
    move-object/from16 v15, p14

    .line 130
    .line 131
    :goto_d
    and-int/lit16 v1, v1, 0x4000

    .line 132
    .line 133
    if-eqz v1, :cond_e

    .line 134
    .line 135
    iget-object v1, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->warnings:Ljava/util/List;

    .line 136
    .line 137
    move-object/from16 p16, v1

    .line 138
    .line 139
    :goto_e
    move-object/from16 p1, v0

    .line 140
    .line 141
    move-object/from16 p2, v2

    .line 142
    .line 143
    move-object/from16 p3, v3

    .line 144
    .line 145
    move-object/from16 p4, v4

    .line 146
    .line 147
    move-object/from16 p5, v5

    .line 148
    .line 149
    move-object/from16 p6, v6

    .line 150
    .line 151
    move-object/from16 p7, v7

    .line 152
    .line 153
    move-object/from16 p8, v8

    .line 154
    .line 155
    move-object/from16 p9, v9

    .line 156
    .line 157
    move-object/from16 p10, v10

    .line 158
    .line 159
    move-object/from16 p11, v11

    .line 160
    .line 161
    move-object/from16 p12, v12

    .line 162
    .line 163
    move-object/from16 p13, v13

    .line 164
    .line 165
    move-object/from16 p14, v14

    .line 166
    .line 167
    move-object/from16 p15, v15

    .line 168
    .line 169
    goto :goto_f

    .line 170
    :cond_e
    move-object/from16 p16, p15

    .line 171
    .line 172
    goto :goto_e

    .line 173
    :goto_f
    invoke-virtual/range {p1 .. p16}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->copy(Ljava/time/OffsetDateTime;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    return-object v0
.end method

.method public static synthetic getAcceptedDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "acceptedDate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getAddOns$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "addOns"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getAppointmentDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "appointmentDate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getBookingId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "bookingId"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getClosedDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "closedDate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getConfirmationDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "confirmationDate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getContactedDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "contactedDate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getCreationDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "creationDate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getExtras$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "extras"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getMileageInKm$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "mileageInKm"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getResolution$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "resolution"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getServicePartner$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "servicePartner"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getType$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "type"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getUpdateDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "updateDate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getWarnings$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "warnings"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->creationDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->updateDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->mileageInKm:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->type:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component13()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->extras:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component14()Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->addOns:Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component15()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->warnings:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->servicePartner:Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->bookingId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->resolution:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->acceptedDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->confirmationDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->closedDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->appointmentDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->contactedDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/time/OffsetDateTime;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;
    .locals 17
    .param p1    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "creationDate"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "servicePartner"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "bookingId"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "resolution"
        .end annotation
    .end param
    .param p5    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "acceptedDate"
        .end annotation
    .end param
    .param p6    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "confirmationDate"
        .end annotation
    .end param
    .param p7    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "closedDate"
        .end annotation
    .end param
    .param p8    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "appointmentDate"
        .end annotation
    .end param
    .param p9    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "contactedDate"
        .end annotation
    .end param
    .param p10    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "updateDate"
        .end annotation
    .end param
    .param p11    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "mileageInKm"
        .end annotation
    .end param
    .param p12    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "type"
        .end annotation
    .end param
    .param p13    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "extras"
        .end annotation
    .end param
    .param p14    # Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "addOns"
        .end annotation
    .end param
    .param p15    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "warnings"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/time/OffsetDateTime;",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/lang/Integer;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;",
            ">;",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;",
            ">;)",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;"
        }
    .end annotation

    .line 1
    const-string v0, "creationDate"

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "servicePartner"

    .line 9
    .line 10
    move-object/from16 v3, p2

    .line 11
    .line 12
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "bookingId"

    .line 16
    .line 17
    move-object/from16 v4, p3

    .line 18
    .line 19
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v0, "resolution"

    .line 23
    .line 24
    move-object/from16 v5, p4

    .line 25
    .line 26
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    new-instance v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;

    .line 30
    .line 31
    move-object/from16 v6, p5

    .line 32
    .line 33
    move-object/from16 v7, p6

    .line 34
    .line 35
    move-object/from16 v8, p7

    .line 36
    .line 37
    move-object/from16 v9, p8

    .line 38
    .line 39
    move-object/from16 v10, p9

    .line 40
    .line 41
    move-object/from16 v11, p10

    .line 42
    .line 43
    move-object/from16 v12, p11

    .line 44
    .line 45
    move-object/from16 v13, p12

    .line 46
    .line 47
    move-object/from16 v14, p13

    .line 48
    .line 49
    move-object/from16 v15, p14

    .line 50
    .line 51
    move-object/from16 v16, p15

    .line 52
    .line 53
    invoke-direct/range {v1 .. v16}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;-><init>(Ljava/time/OffsetDateTime;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;)V

    .line 54
    .line 55
    .line 56
    return-object v1
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->creationDate:Ljava/time/OffsetDateTime;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->creationDate:Ljava/time/OffsetDateTime;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->servicePartner:Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->servicePartner:Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->bookingId:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->bookingId:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->resolution:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->resolution:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->acceptedDate:Ljava/time/OffsetDateTime;

    .line 58
    .line 59
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->acceptedDate:Ljava/time/OffsetDateTime;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->confirmationDate:Ljava/time/OffsetDateTime;

    .line 69
    .line 70
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->confirmationDate:Ljava/time/OffsetDateTime;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->closedDate:Ljava/time/OffsetDateTime;

    .line 80
    .line 81
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->closedDate:Ljava/time/OffsetDateTime;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->appointmentDate:Ljava/time/OffsetDateTime;

    .line 91
    .line 92
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->appointmentDate:Ljava/time/OffsetDateTime;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_9

    .line 99
    .line 100
    return v2

    .line 101
    :cond_9
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->contactedDate:Ljava/time/OffsetDateTime;

    .line 102
    .line 103
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->contactedDate:Ljava/time/OffsetDateTime;

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_a

    .line 110
    .line 111
    return v2

    .line 112
    :cond_a
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->updateDate:Ljava/time/OffsetDateTime;

    .line 113
    .line 114
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->updateDate:Ljava/time/OffsetDateTime;

    .line 115
    .line 116
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-nez v1, :cond_b

    .line 121
    .line 122
    return v2

    .line 123
    :cond_b
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->mileageInKm:Ljava/lang/Integer;

    .line 124
    .line 125
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->mileageInKm:Ljava/lang/Integer;

    .line 126
    .line 127
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    if-nez v1, :cond_c

    .line 132
    .line 133
    return v2

    .line 134
    :cond_c
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->type:Ljava/lang/String;

    .line 135
    .line 136
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->type:Ljava/lang/String;

    .line 137
    .line 138
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-nez v1, :cond_d

    .line 143
    .line 144
    return v2

    .line 145
    :cond_d
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->extras:Ljava/util/List;

    .line 146
    .line 147
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->extras:Ljava/util/List;

    .line 148
    .line 149
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-nez v1, :cond_e

    .line 154
    .line 155
    return v2

    .line 156
    :cond_e
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->addOns:Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    .line 157
    .line 158
    iget-object v3, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->addOns:Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    .line 159
    .line 160
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    if-nez v1, :cond_f

    .line 165
    .line 166
    return v2

    .line 167
    :cond_f
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->warnings:Ljava/util/List;

    .line 168
    .line 169
    iget-object p1, p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->warnings:Ljava/util/List;

    .line 170
    .line 171
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result p0

    .line 175
    if-nez p0, :cond_10

    .line 176
    .line 177
    return v2

    .line 178
    :cond_10
    return v0
.end method

.method public final getAcceptedDate()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->acceptedDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAddOns()Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->addOns:Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAppointmentDate()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->appointmentDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getBookingId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->bookingId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getClosedDate()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->closedDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getConfirmationDate()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->confirmationDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getContactedDate()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->contactedDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCreationDate()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->creationDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getExtras()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->extras:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMileageInKm()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->mileageInKm:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getResolution()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->resolution:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getServicePartner()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->servicePartner:Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->type:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUpdateDate()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->updateDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWarnings()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->warnings:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->creationDate:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->servicePartner:Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 11
    .line 12
    invoke-virtual {v2}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->bookingId:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->resolution:Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->acceptedDate:Ljava/time/OffsetDateTime;

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    if-nez v2, :cond_0

    .line 34
    .line 35
    move v2, v3

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v2}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    :goto_0
    add-int/2addr v0, v2

    .line 42
    mul-int/2addr v0, v1

    .line 43
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->confirmationDate:Ljava/time/OffsetDateTime;

    .line 44
    .line 45
    if-nez v2, :cond_1

    .line 46
    .line 47
    move v2, v3

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    invoke-virtual {v2}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    :goto_1
    add-int/2addr v0, v2

    .line 54
    mul-int/2addr v0, v1

    .line 55
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->closedDate:Ljava/time/OffsetDateTime;

    .line 56
    .line 57
    if-nez v2, :cond_2

    .line 58
    .line 59
    move v2, v3

    .line 60
    goto :goto_2

    .line 61
    :cond_2
    invoke-virtual {v2}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    :goto_2
    add-int/2addr v0, v2

    .line 66
    mul-int/2addr v0, v1

    .line 67
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->appointmentDate:Ljava/time/OffsetDateTime;

    .line 68
    .line 69
    if-nez v2, :cond_3

    .line 70
    .line 71
    move v2, v3

    .line 72
    goto :goto_3

    .line 73
    :cond_3
    invoke-virtual {v2}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    :goto_3
    add-int/2addr v0, v2

    .line 78
    mul-int/2addr v0, v1

    .line 79
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->contactedDate:Ljava/time/OffsetDateTime;

    .line 80
    .line 81
    if-nez v2, :cond_4

    .line 82
    .line 83
    move v2, v3

    .line 84
    goto :goto_4

    .line 85
    :cond_4
    invoke-virtual {v2}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    :goto_4
    add-int/2addr v0, v2

    .line 90
    mul-int/2addr v0, v1

    .line 91
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->updateDate:Ljava/time/OffsetDateTime;

    .line 92
    .line 93
    if-nez v2, :cond_5

    .line 94
    .line 95
    move v2, v3

    .line 96
    goto :goto_5

    .line 97
    :cond_5
    invoke-virtual {v2}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    :goto_5
    add-int/2addr v0, v2

    .line 102
    mul-int/2addr v0, v1

    .line 103
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->mileageInKm:Ljava/lang/Integer;

    .line 104
    .line 105
    if-nez v2, :cond_6

    .line 106
    .line 107
    move v2, v3

    .line 108
    goto :goto_6

    .line 109
    :cond_6
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    :goto_6
    add-int/2addr v0, v2

    .line 114
    mul-int/2addr v0, v1

    .line 115
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->type:Ljava/lang/String;

    .line 116
    .line 117
    if-nez v2, :cond_7

    .line 118
    .line 119
    move v2, v3

    .line 120
    goto :goto_7

    .line 121
    :cond_7
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    :goto_7
    add-int/2addr v0, v2

    .line 126
    mul-int/2addr v0, v1

    .line 127
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->extras:Ljava/util/List;

    .line 128
    .line 129
    if-nez v2, :cond_8

    .line 130
    .line 131
    move v2, v3

    .line 132
    goto :goto_8

    .line 133
    :cond_8
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    :goto_8
    add-int/2addr v0, v2

    .line 138
    mul-int/2addr v0, v1

    .line 139
    iget-object v2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->addOns:Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    .line 140
    .line 141
    if-nez v2, :cond_9

    .line 142
    .line 143
    move v2, v3

    .line 144
    goto :goto_9

    .line 145
    :cond_9
    invoke-virtual {v2}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;->hashCode()I

    .line 146
    .line 147
    .line 148
    move-result v2

    .line 149
    :goto_9
    add-int/2addr v0, v2

    .line 150
    mul-int/2addr v0, v1

    .line 151
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->warnings:Ljava/util/List;

    .line 152
    .line 153
    if-nez p0, :cond_a

    .line 154
    .line 155
    goto :goto_a

    .line 156
    :cond_a
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 157
    .line 158
    .line 159
    move-result v3

    .line 160
    :goto_a
    add-int/2addr v0, v3

    .line 161
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->creationDate:Ljava/time/OffsetDateTime;

    .line 4
    .line 5
    iget-object v2, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->servicePartner:Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 6
    .line 7
    iget-object v3, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->bookingId:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->resolution:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->acceptedDate:Ljava/time/OffsetDateTime;

    .line 12
    .line 13
    iget-object v6, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->confirmationDate:Ljava/time/OffsetDateTime;

    .line 14
    .line 15
    iget-object v7, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->closedDate:Ljava/time/OffsetDateTime;

    .line 16
    .line 17
    iget-object v8, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->appointmentDate:Ljava/time/OffsetDateTime;

    .line 18
    .line 19
    iget-object v9, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->contactedDate:Ljava/time/OffsetDateTime;

    .line 20
    .line 21
    iget-object v10, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->updateDate:Ljava/time/OffsetDateTime;

    .line 22
    .line 23
    iget-object v11, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->mileageInKm:Ljava/lang/Integer;

    .line 24
    .line 25
    iget-object v12, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->type:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v13, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->extras:Ljava/util/List;

    .line 28
    .line 29
    iget-object v14, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->addOns:Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    .line 30
    .line 31
    iget-object v0, v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->warnings:Ljava/util/List;

    .line 32
    .line 33
    new-instance v15, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    move-object/from16 p0, v0

    .line 36
    .line 37
    const-string v0, "CustomerServiceBookingDto(creationDate="

    .line 38
    .line 39
    invoke-direct {v15, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v15, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v0, ", servicePartner="

    .line 46
    .line 47
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v15, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v0, ", bookingId="

    .line 54
    .line 55
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    const-string v0, ", resolution="

    .line 59
    .line 60
    const-string v1, ", acceptedDate="

    .line 61
    .line 62
    invoke-static {v15, v3, v0, v4, v1}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v15, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v0, ", confirmationDate="

    .line 69
    .line 70
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v15, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v0, ", closedDate="

    .line 77
    .line 78
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v15, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v0, ", appointmentDate="

    .line 85
    .line 86
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v15, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v0, ", contactedDate="

    .line 93
    .line 94
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v15, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string v0, ", updateDate="

    .line 101
    .line 102
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v15, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string v0, ", mileageInKm="

    .line 109
    .line 110
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v15, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    const-string v0, ", type="

    .line 117
    .line 118
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v15, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    const-string v0, ", extras="

    .line 125
    .line 126
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v15, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    const-string v0, ", addOns="

    .line 133
    .line 134
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    invoke-virtual {v15, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    const-string v0, ", warnings="

    .line 141
    .line 142
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    const-string v0, ")"

    .line 146
    .line 147
    move-object/from16 v1, p0

    .line 148
    .line 149
    invoke-static {v15, v1, v0}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    return-object v0
.end method
