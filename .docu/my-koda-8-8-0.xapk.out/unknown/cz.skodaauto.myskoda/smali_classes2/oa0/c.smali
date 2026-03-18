.class public final synthetic Loa0/c;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Loa0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Loa0/c;

    .line 2
    .line 3
    const-string v4, "toModel(Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;)Lcz/skodaauto/myskoda/feature/wakeup/model/ReadinessStatus;"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x1

    .line 7
    const-class v2, Loa0/b;

    .line 8
    .line 9
    const-string v3, "toModel"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Loa0/c;->d:Loa0/c;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;

    .line 2
    .line 3
    const-string p0, "p0"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->getInMotion()Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    invoke-virtual {p1}, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->getUnreachable()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    invoke-virtual {p1}, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->getIgnitionOn()Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    invoke-virtual {p1}, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->getBatteryProtectionLimitOn()Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    invoke-virtual {p1}, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->getSoftwareUpdateStatus()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    const-string p1, "UPDATE_IN_PROGRESS"

    .line 29
    .line 30
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    if-eqz p1, :cond_0

    .line 35
    .line 36
    sget-object p0, Lra0/b;->f:Lra0/b;

    .line 37
    .line 38
    :goto_0
    move-object v5, p0

    .line 39
    goto :goto_1

    .line 40
    :cond_0
    const-string p1, "UPDATE_FAILED"

    .line 41
    .line 42
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_1

    .line 47
    .line 48
    sget-object p0, Lra0/b;->e:Lra0/b;

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    sget-object p0, Lra0/b;->d:Lra0/b;

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :goto_1
    new-instance v0, Lra0/a;

    .line 55
    .line 56
    invoke-direct/range {v0 .. v5}, Lra0/a;-><init>(ZZZZLra0/b;)V

    .line 57
    .line 58
    .line 59
    return-object v0
.end method
