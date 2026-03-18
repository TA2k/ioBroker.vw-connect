.class public Lgz0/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
    with = Lmz0/l;
.end annotation


# static fields
.field public static final Companion:Lgz0/a0;

.field public static final b:Lgz0/n;


# instance fields
.field public final a:Ljava/time/ZoneId;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lgz0/a0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgz0/b0;->Companion:Lgz0/a0;

    .line 7
    .line 8
    new-instance v0, Lgz0/n;

    .line 9
    .line 10
    sget-object v1, Lgz0/d0;->Companion:Lgz0/c0;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    sget-object v1, Lgz0/d0;->e:Lgz0/d0;

    .line 16
    .line 17
    const-string v2, "UTC"

    .line 18
    .line 19
    invoke-static {v2}, Ljava/time/ZoneId;->of(Ljava/lang/String;)Ljava/time/ZoneId;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const-string v3, "of(...)"

    .line 24
    .line 25
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string v3, "offset"

    .line 29
    .line 30
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-direct {v0, v2}, Lgz0/b0;-><init>(Ljava/time/ZoneId;)V

    .line 34
    .line 35
    .line 36
    sput-object v0, Lgz0/b0;->b:Lgz0/n;

    .line 37
    .line 38
    return-void
.end method

.method public constructor <init>(Ljava/time/ZoneId;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgz0/b0;->a:Ljava/time/ZoneId;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lgz0/b0;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lgz0/b0;

    .line 8
    .line 9
    iget-object p1, p1, Lgz0/b0;->a:Ljava/time/ZoneId;

    .line 10
    .line 11
    iget-object p0, p0, Lgz0/b0;->a:Ljava/time/ZoneId;

    .line 12
    .line 13
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0

    .line 22
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lgz0/b0;->a:Ljava/time/ZoneId;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/time/ZoneId;->hashCode()I

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
    iget-object p0, p0, Lgz0/b0;->a:Ljava/time/ZoneId;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/time/ZoneId;->toString()Ljava/lang/String;

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
