.class public final synthetic Lm20/c;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Lm20/c;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lm20/c;

    .line 2
    .line 3
    const-string v4, "toModel(Lcz/myskoda/api/bff_garage/v2/VehicleFleetDto;)Z"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x1

    .line 7
    const-class v2, Lm20/k;

    .line 8
    .line 9
    const-string v3, "toModel"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lm20/c;->d:Lm20/c;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lcz/myskoda/api/bff_garage/v2/VehicleFleetDto;

    .line 2
    .line 3
    const-string p0, "p0"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lcz/myskoda/api/bff_garage/v2/VehicleFleetDto;->getPartOfFleet()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    new-instance p1, Lp20/a;

    .line 13
    .line 14
    invoke-direct {p1, p0}, Lp20/a;-><init>(Z)V

    .line 15
    .line 16
    .line 17
    return-object p1
.end method
