.class public final Lag/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Lag/w;


# instance fields
.field public final a:Llc/q;

.field public final b:Ljp/a1;

.field public final c:Z

.field public final d:Ljava/lang/String;

.field public final e:Lag/k;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lag/w;

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
    new-instance v2, Lag/f;

    .line 11
    .line 12
    sget-object v3, Lag/e;->e:Lag/e;

    .line 13
    .line 14
    sget-object v4, Lag/l;->d:Lag/l;

    .line 15
    .line 16
    invoke-direct {v2, v3, v4}, Lag/f;-><init>(Lag/e;Lag/l;)V

    .line 17
    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    sget-object v5, Lag/h;->a:Lag/h;

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    invoke-direct/range {v0 .. v5}, Lag/w;-><init>(Llc/q;Ljp/a1;ZLjava/lang/String;Lag/k;)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lag/w;->f:Lag/w;

    .line 27
    .line 28
    return-void
.end method

.method public constructor <init>(Llc/q;Ljp/a1;ZLjava/lang/String;Lag/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lag/w;->a:Llc/q;

    .line 5
    .line 6
    iput-object p2, p0, Lag/w;->b:Ljp/a1;

    .line 7
    .line 8
    iput-boolean p3, p0, Lag/w;->c:Z

    .line 9
    .line 10
    iput-object p4, p0, Lag/w;->d:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lag/w;->e:Lag/k;

    .line 13
    .line 14
    return-void
.end method

.method public static a(Lag/w;Llc/q;Ljp/a1;Lag/k;I)Lag/w;
    .locals 6

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lag/w;->a:Llc/q;

    .line 6
    .line 7
    :cond_0
    move-object v1, p1

    .line 8
    and-int/lit8 p1, p4, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-object p2, p0, Lag/w;->b:Ljp/a1;

    .line 13
    .line 14
    :cond_1
    move-object v2, p2

    .line 15
    iget-boolean v3, p0, Lag/w;->c:Z

    .line 16
    .line 17
    iget-object v4, p0, Lag/w;->d:Ljava/lang/String;

    .line 18
    .line 19
    and-int/lit8 p1, p4, 0x10

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    iget-object p3, p0, Lag/w;->e:Lag/k;

    .line 24
    .line 25
    :cond_2
    move-object v5, p3

    .line 26
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    const-string p0, "state"

    .line 30
    .line 31
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string p0, "ui"

    .line 35
    .line 36
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string p0, "goto"

    .line 40
    .line 41
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v0, Lag/w;

    .line 45
    .line 46
    invoke-direct/range {v0 .. v5}, Lag/w;-><init>(Llc/q;Ljp/a1;ZLjava/lang/String;Lag/k;)V

    .line 47
    .line 48
    .line 49
    return-object v0
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
    instance-of v1, p1, Lag/w;

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
    check-cast p1, Lag/w;

    .line 12
    .line 13
    iget-object v1, p0, Lag/w;->a:Llc/q;

    .line 14
    .line 15
    iget-object v3, p1, Lag/w;->a:Llc/q;

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
    iget-object v1, p0, Lag/w;->b:Ljp/a1;

    .line 25
    .line 26
    iget-object v3, p1, Lag/w;->b:Ljp/a1;

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
    iget-boolean v1, p0, Lag/w;->c:Z

    .line 36
    .line 37
    iget-boolean v3, p1, Lag/w;->c:Z

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lag/w;->d:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lag/w;->d:Ljava/lang/String;

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
    iget-object p0, p0, Lag/w;->e:Lag/k;

    .line 54
    .line 55
    iget-object p1, p1, Lag/w;->e:Lag/k;

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
    iget-object v0, p0, Lag/w;->a:Llc/q;

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
    const/16 v1, 0x1f

    .line 10
    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-object v2, p0, Lag/w;->b:Ljp/a1;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    add-int/2addr v2, v0

    .line 19
    mul-int/2addr v2, v1

    .line 20
    iget-boolean v0, p0, Lag/w;->c:Z

    .line 21
    .line 22
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-object v2, p0, Lag/w;->d:Ljava/lang/String;

    .line 27
    .line 28
    if-nez v2, :cond_0

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    :goto_0
    add-int/2addr v0, v2

    .line 37
    mul-int/2addr v0, v1

    .line 38
    iget-object p0, p0, Lag/w;->e:Lag/k;

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    add-int/2addr p0, v0

    .line 45
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

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
    iget-object v1, p0, Lag/w;->a:Llc/q;

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
    iget-object v1, p0, Lag/w;->b:Ljp/a1;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", shouldShowVehiclePopup="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", pcid="

    .line 29
    .line 30
    const-string v2, ", goto="

    .line 31
    .line 32
    iget-object v3, p0, Lag/w;->d:Ljava/lang/String;

    .line 33
    .line 34
    iget-boolean v4, p0, Lag/w;->c:Z

    .line 35
    .line 36
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Lag/w;->e:Lag/k;

    .line 40
    .line 41
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string p0, ")"

    .line 45
    .line 46
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method
