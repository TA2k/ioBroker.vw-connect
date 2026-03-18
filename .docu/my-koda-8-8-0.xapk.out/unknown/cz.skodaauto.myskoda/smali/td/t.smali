.class public final Ltd/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Ltd/t;


# instance fields
.field public final a:Llc/q;

.field public final b:Ltd/p;

.field public final c:Ltd/s;

.field public final d:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    new-instance v0, Ltd/t;

    .line 2
    .line 3
    new-instance v1, Llc/q;

    .line 4
    .line 5
    sget-object v2, Llc/a;->c:Llc/c;

    .line 6
    .line 7
    invoke-direct {v1, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    new-instance v3, Ltd/p;

    .line 11
    .line 12
    const-string v8, ""

    .line 13
    .line 14
    const/16 v10, 0x48

    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x0

    .line 18
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 19
    .line 20
    const/4 v7, 0x0

    .line 21
    move-object v9, v6

    .line 22
    invoke-direct/range {v3 .. v10}, Ltd/p;-><init>(Ljava/lang/String;ZLjava/util/List;ZLjava/lang/String;Ljava/util/List;I)V

    .line 23
    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    const/16 v4, 0xc

    .line 27
    .line 28
    invoke-direct {v0, v1, v3, v2, v4}, Ltd/t;-><init>(Llc/q;Ltd/p;Ljava/util/Set;I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Ltd/t;->e:Ltd/t;

    .line 32
    .line 33
    return-void
.end method

.method public synthetic constructor <init>(Llc/q;Ltd/p;Ljava/util/Set;I)V
    .locals 0

    and-int/lit8 p4, p4, 0x8

    if-eqz p4, :cond_0

    .line 6
    sget-object p3, Lmx0/u;->d:Lmx0/u;

    .line 7
    :cond_0
    sget-object p4, Ltd/r;->a:Ltd/r;

    invoke-direct {p0, p1, p2, p4, p3}, Ltd/t;-><init>(Llc/q;Ltd/p;Ltd/s;Ljava/util/Set;)V

    return-void
.end method

.method public constructor <init>(Llc/q;Ltd/p;Ltd/s;Ljava/util/Set;)V
    .locals 1

    const-string v0, "selectedFilters"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ltd/t;->a:Llc/q;

    .line 3
    iput-object p2, p0, Ltd/t;->b:Ltd/p;

    .line 4
    iput-object p3, p0, Ltd/t;->c:Ltd/s;

    .line 5
    iput-object p4, p0, Ltd/t;->d:Ljava/util/Set;

    return-void
.end method

.method public static a(Ltd/t;Llc/q;Ltd/p;Ltd/s;Ljava/util/Set;I)Ltd/t;
    .locals 1

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltd/t;->a:Llc/q;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p5, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltd/t;->b:Ltd/p;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 v0, p5, 0x4

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Ltd/t;->c:Ltd/s;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Ltd/t;->d:Ljava/util/Set;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    const-string p0, "state"

    .line 29
    .line 30
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string p0, "ui"

    .line 34
    .line 35
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string p0, "goto"

    .line 39
    .line 40
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const-string p0, "selectedFilters"

    .line 44
    .line 45
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    new-instance p0, Ltd/t;

    .line 49
    .line 50
    invoke-direct {p0, p1, p2, p3, p4}, Ltd/t;-><init>(Llc/q;Ltd/p;Ltd/s;Ljava/util/Set;)V

    .line 51
    .line 52
    .line 53
    return-object p0
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
    instance-of v1, p1, Ltd/t;

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
    check-cast p1, Ltd/t;

    .line 12
    .line 13
    iget-object v1, p0, Ltd/t;->a:Llc/q;

    .line 14
    .line 15
    iget-object v3, p1, Ltd/t;->a:Llc/q;

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
    iget-object v1, p0, Ltd/t;->b:Ltd/p;

    .line 25
    .line 26
    iget-object v3, p1, Ltd/t;->b:Ltd/p;

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
    iget-object v1, p0, Ltd/t;->c:Ltd/s;

    .line 36
    .line 37
    iget-object v3, p1, Ltd/t;->c:Ltd/s;

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
    iget-object p0, p0, Ltd/t;->d:Ljava/util/Set;

    .line 47
    .line 48
    iget-object p1, p1, Ltd/t;->d:Ljava/util/Set;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Ltd/t;->a:Llc/q;

    .line 2
    .line 3
    iget-object v0, v0, Llc/q;->a:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    mul-int/lit8 v0, v0, 0x1f

    .line 10
    .line 11
    iget-object v1, p0, Ltd/t;->b:Ltd/p;

    .line 12
    .line 13
    invoke-virtual {v1}, Ltd/p;->hashCode()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    add-int/2addr v1, v0

    .line 18
    mul-int/lit8 v1, v1, 0x1f

    .line 19
    .line 20
    iget-object v0, p0, Ltd/t;->c:Ltd/s;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    add-int/2addr v0, v1

    .line 27
    mul-int/lit8 v0, v0, 0x1f

    .line 28
    .line 29
    iget-object p0, p0, Ltd/t;->d:Ljava/util/Set;

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    add-int/2addr p0, v0

    .line 36
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ViewModelState(state="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ltd/t;->a:Llc/q;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", ui="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ltd/t;->b:Ltd/p;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", goto="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ltd/t;->c:Ltd/s;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", selectedFilters="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Ltd/t;->d:Ljava/util/Set;

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
