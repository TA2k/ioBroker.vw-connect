.class public final Lgz0/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# annotations
.annotation runtime Lqz0/g;
    with = Lmz0/m;
.end annotation


# static fields
.field public static final Companion:Lgz0/c0;

.field public static final e:Lgz0/d0;


# instance fields
.field public final d:Ljava/time/ZoneOffset;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lgz0/c0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgz0/d0;->Companion:Lgz0/c0;

    .line 7
    .line 8
    new-instance v0, Lgz0/d0;

    .line 9
    .line 10
    sget-object v1, Ljava/time/ZoneOffset;->UTC:Ljava/time/ZoneOffset;

    .line 11
    .line 12
    const-string v2, "UTC"

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {v0, v1}, Lgz0/d0;-><init>(Ljava/time/ZoneOffset;)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lgz0/d0;->e:Lgz0/d0;

    .line 21
    .line 22
    return-void
.end method

.method public constructor <init>(Ljava/time/ZoneOffset;)V
    .locals 1

    .line 1
    const-string v0, "zoneOffset"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lgz0/d0;->d:Ljava/time/ZoneOffset;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lgz0/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lgz0/d0;

    .line 6
    .line 7
    iget-object p1, p1, Lgz0/d0;->d:Ljava/time/ZoneOffset;

    .line 8
    .line 9
    iget-object p0, p0, Lgz0/d0;->d:Ljava/time/ZoneOffset;

    .line 10
    .line 11
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lgz0/d0;->d:Ljava/time/ZoneOffset;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/time/ZoneOffset;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Lgz0/d0;->d:Ljava/time/ZoneOffset;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/time/ZoneOffset;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "toString(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method
