.class public final Lc61/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lc61/b;

.field public static final f:[Llx0/i;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/util/Map;

.field public final c:Lz51/c;

.field public final d:Lgz0/w;

.field public final e:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lc61/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc61/c;->Companion:Lc61/b;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Lc00/f1;

    .line 11
    .line 12
    const/4 v2, 0x6

    .line 13
    invoke-direct {v1, v2}, Lc00/f1;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    new-instance v2, Lc00/f1;

    .line 21
    .line 22
    const/4 v3, 0x7

    .line 23
    invoke-direct {v2, v3}, Lc00/f1;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    const/4 v2, 0x5

    .line 31
    new-array v2, v2, [Llx0/i;

    .line 32
    .line 33
    const/4 v3, 0x0

    .line 34
    const/4 v4, 0x0

    .line 35
    aput-object v4, v2, v3

    .line 36
    .line 37
    const/4 v3, 0x1

    .line 38
    aput-object v1, v2, v3

    .line 39
    .line 40
    const/4 v1, 0x2

    .line 41
    aput-object v0, v2, v1

    .line 42
    .line 43
    const/4 v0, 0x3

    .line 44
    aput-object v4, v2, v0

    .line 45
    .line 46
    const/4 v0, 0x4

    .line 47
    aput-object v4, v2, v0

    .line 48
    .line 49
    sput-object v2, Lc61/c;->f:[Llx0/i;

    .line 50
    .line 51
    return-void
.end method

.method public constructor <init>(ILjava/lang/String;Ljava/util/Map;Lz51/c;Lgz0/w;Ljava/lang/String;)V
    .locals 2

    and-int/lit8 v0, p1, 0x7

    const/4 v1, 0x7

    if-ne v1, v0, :cond_2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lc61/c;->a:Ljava/lang/String;

    iput-object p3, p0, Lc61/c;->b:Ljava/util/Map;

    iput-object p4, p0, Lc61/c;->c:Lz51/c;

    and-int/lit8 p2, p1, 0x8

    if-nez p2, :cond_0

    .line 2
    sget-object p2, Lmy0/g;->a:Lmy0/b;

    invoke-interface {p2}, Lmy0/b;->now()Lmy0/f;

    move-result-object p2

    .line 3
    sget-object p3, Lgz0/b0;->Companion:Lgz0/a0;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Lgz0/a0;->a()Lgz0/b0;

    move-result-object p3

    invoke-static {p2, p3}, Lkp/u9;->f(Lmy0/f;Lgz0/b0;)Lgz0/w;

    move-result-object p2

    .line 4
    iput-object p2, p0, Lc61/c;->d:Lgz0/w;

    goto :goto_0

    :cond_0
    iput-object p5, p0, Lc61/c;->d:Lgz0/w;

    :goto_0
    and-int/lit8 p1, p1, 0x10

    if-nez p1, :cond_1

    .line 5
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object p1

    invoke-virtual {p1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object p1

    const-string p2, "toString(...)"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    iput-object p1, p0, Lc61/c;->e:Ljava/lang/String;

    return-void

    :cond_1
    iput-object p6, p0, Lc61/c;->e:Ljava/lang/String;

    return-void

    :cond_2
    sget-object p0, Lc61/a;->a:Lc61/a;

    invoke-virtual {p0}, Lc61/a;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v1, p0}, Luz0/b1;->l(IILsz0/g;)V

    const/4 p0, 0x0

    throw p0
.end method

.method public constructor <init>(Lgz0/w;)V
    .locals 3

    .line 7
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v0

    invoke-virtual {v0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "toString(...)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    const-string v1, "message"

    const/4 v2, 0x0

    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "attributes"

    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "logLevel"

    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    iput-object v2, p0, Lc61/c;->a:Ljava/lang/String;

    .line 11
    iput-object v2, p0, Lc61/c;->b:Ljava/util/Map;

    .line 12
    iput-object v2, p0, Lc61/c;->c:Lz51/c;

    .line 13
    iput-object p1, p0, Lc61/c;->d:Lgz0/w;

    .line 14
    iput-object v0, p0, Lc61/c;->e:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
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
    instance-of v1, p1, Lc61/c;

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
    check-cast p1, Lc61/c;

    .line 12
    .line 13
    iget-object v1, p0, Lc61/c;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lc61/c;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lc61/c;->b:Ljava/util/Map;

    .line 25
    .line 26
    iget-object v3, p1, Lc61/c;->b:Ljava/util/Map;

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
    iget-object v1, p0, Lc61/c;->c:Lz51/c;

    .line 36
    .line 37
    iget-object v3, p1, Lc61/c;->c:Lz51/c;

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lc61/c;->d:Lgz0/w;

    .line 43
    .line 44
    iget-object v3, p1, Lc61/c;->d:Lgz0/w;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object p0, p0, Lc61/c;->e:Ljava/lang/String;

    .line 54
    .line 55
    iget-object p1, p1, Lc61/c;->e:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    if-nez p0, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lc61/c;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Lc61/c;->b:Ljava/util/Map;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lp3/m;->a(IILjava/util/Map;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lc61/c;->c:Lz51/c;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object v0, p0, Lc61/c;->d:Lgz0/w;

    .line 25
    .line 26
    iget-object v0, v0, Lgz0/w;->d:Ljava/time/LocalDateTime;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/time/LocalDateTime;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    add-int/2addr v0, v2

    .line 33
    mul-int/2addr v0, v1

    .line 34
    iget-object p0, p0, Lc61/c;->e:Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    add-int/2addr p0, v0

    .line 41
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Log(message="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lc61/c;->a:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", attributes="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lc61/c;->b:Ljava/util/Map;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", logLevel="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lc61/c;->c:Lz51/c;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", timestamp="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lc61/c;->d:Lgz0/w;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", id="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ")"

    .line 49
    .line 50
    iget-object p0, p0, Lc61/c;->e:Ljava/lang/String;

    .line 51
    .line 52
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
