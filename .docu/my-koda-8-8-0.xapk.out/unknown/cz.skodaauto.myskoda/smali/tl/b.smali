.class public final Ltl/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lvy0/x;

.field public final b:Lvy0/x;

.field public final c:Lvy0/x;

.field public final d:Lvy0/x;

.field public final e:Lwl/c;

.field public final f:Lul/d;

.field public final g:Landroid/graphics/Bitmap$Config;

.field public final h:Z

.field public final i:Ltl/a;

.field public final j:Ltl/a;

.field public final k:Ltl/a;


# direct methods
.method public constructor <init>()V
    .locals 5

    .line 1
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 2
    .line 3
    sget-object v0, Laz0/m;->a:Lwy0/c;

    .line 4
    .line 5
    iget-object v0, v0, Lwy0/c;->h:Lwy0/c;

    .line 6
    .line 7
    sget-object v1, Lcz0/d;->e:Lcz0/d;

    .line 8
    .line 9
    sget-object v2, Lul/d;->f:Lul/d;

    .line 10
    .line 11
    sget-object v3, Lxl/c;->b:Landroid/graphics/Bitmap$Config;

    .line 12
    .line 13
    sget-object v4, Ltl/a;->f:Ltl/a;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Ltl/b;->a:Lvy0/x;

    .line 19
    .line 20
    iput-object v1, p0, Ltl/b;->b:Lvy0/x;

    .line 21
    .line 22
    iput-object v1, p0, Ltl/b;->c:Lvy0/x;

    .line 23
    .line 24
    iput-object v1, p0, Ltl/b;->d:Lvy0/x;

    .line 25
    .line 26
    sget-object v0, Lwl/e;->a:Lwl/c;

    .line 27
    .line 28
    iput-object v0, p0, Ltl/b;->e:Lwl/c;

    .line 29
    .line 30
    iput-object v2, p0, Ltl/b;->f:Lul/d;

    .line 31
    .line 32
    iput-object v3, p0, Ltl/b;->g:Landroid/graphics/Bitmap$Config;

    .line 33
    .line 34
    const/4 v0, 0x1

    .line 35
    iput-boolean v0, p0, Ltl/b;->h:Z

    .line 36
    .line 37
    iput-object v4, p0, Ltl/b;->i:Ltl/a;

    .line 38
    .line 39
    iput-object v4, p0, Ltl/b;->j:Ltl/a;

    .line 40
    .line 41
    iput-object v4, p0, Ltl/b;->k:Ltl/a;

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    instance-of v0, p1, Ltl/b;

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    check-cast p1, Ltl/b;

    .line 9
    .line 10
    iget-object v0, p1, Ltl/b;->a:Lvy0/x;

    .line 11
    .line 12
    iget-object v1, p0, Ltl/b;->a:Lvy0/x;

    .line 13
    .line 14
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    iget-object v0, p0, Ltl/b;->b:Lvy0/x;

    .line 21
    .line 22
    iget-object v1, p1, Ltl/b;->b:Lvy0/x;

    .line 23
    .line 24
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    iget-object v0, p0, Ltl/b;->c:Lvy0/x;

    .line 31
    .line 32
    iget-object v1, p1, Ltl/b;->c:Lvy0/x;

    .line 33
    .line 34
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_1

    .line 39
    .line 40
    iget-object v0, p0, Ltl/b;->d:Lvy0/x;

    .line 41
    .line 42
    iget-object v1, p1, Ltl/b;->d:Lvy0/x;

    .line 43
    .line 44
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    iget-object v0, p0, Ltl/b;->e:Lwl/c;

    .line 51
    .line 52
    iget-object v1, p1, Ltl/b;->e:Lwl/c;

    .line 53
    .line 54
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_1

    .line 59
    .line 60
    iget-object v0, p0, Ltl/b;->f:Lul/d;

    .line 61
    .line 62
    iget-object v1, p1, Ltl/b;->f:Lul/d;

    .line 63
    .line 64
    if-ne v0, v1, :cond_1

    .line 65
    .line 66
    iget-object v0, p0, Ltl/b;->g:Landroid/graphics/Bitmap$Config;

    .line 67
    .line 68
    iget-object v1, p1, Ltl/b;->g:Landroid/graphics/Bitmap$Config;

    .line 69
    .line 70
    if-ne v0, v1, :cond_1

    .line 71
    .line 72
    iget-boolean v0, p0, Ltl/b;->h:Z

    .line 73
    .line 74
    iget-boolean v1, p1, Ltl/b;->h:Z

    .line 75
    .line 76
    if-ne v0, v1, :cond_1

    .line 77
    .line 78
    iget-object v0, p0, Ltl/b;->i:Ltl/a;

    .line 79
    .line 80
    iget-object v1, p1, Ltl/b;->i:Ltl/a;

    .line 81
    .line 82
    if-ne v0, v1, :cond_1

    .line 83
    .line 84
    iget-object v0, p0, Ltl/b;->j:Ltl/a;

    .line 85
    .line 86
    iget-object v1, p1, Ltl/b;->j:Ltl/a;

    .line 87
    .line 88
    if-ne v0, v1, :cond_1

    .line 89
    .line 90
    iget-object p0, p0, Ltl/b;->k:Ltl/a;

    .line 91
    .line 92
    iget-object p1, p1, Ltl/b;->k:Ltl/a;

    .line 93
    .line 94
    if-ne p0, p1, :cond_1

    .line 95
    .line 96
    :goto_0
    const/4 p0, 0x1

    .line 97
    return p0

    .line 98
    :cond_1
    const/4 p0, 0x0

    .line 99
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ltl/b;->a:Lvy0/x;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Ltl/b;->b:Lvy0/x;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-object v0, p0, Ltl/b;->c:Lvy0/x;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget-object v2, p0, Ltl/b;->d:Lvy0/x;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    add-int/2addr v2, v0

    .line 33
    mul-int/2addr v2, v1

    .line 34
    iget-object v0, p0, Ltl/b;->e:Lwl/c;

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    const-class v0, Lwl/c;

    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    add-int/2addr v0, v2

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-object v2, p0, Ltl/b;->f:Lul/d;

    .line 48
    .line 49
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    add-int/2addr v2, v0

    .line 54
    mul-int/2addr v2, v1

    .line 55
    iget-object v0, p0, Ltl/b;->g:Landroid/graphics/Bitmap$Config;

    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    add-int/2addr v0, v2

    .line 62
    mul-int/2addr v0, v1

    .line 63
    iget-boolean v2, p0, Ltl/b;->h:Z

    .line 64
    .line 65
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    const/4 v2, 0x0

    .line 70
    const v3, 0xe1781

    .line 71
    .line 72
    .line 73
    invoke-static {v0, v3, v2}, La7/g0;->e(IIZ)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    iget-object v2, p0, Ltl/b;->i:Ltl/a;

    .line 78
    .line 79
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    add-int/2addr v2, v0

    .line 84
    mul-int/2addr v2, v1

    .line 85
    iget-object v0, p0, Ltl/b;->j:Ltl/a;

    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    add-int/2addr v0, v2

    .line 92
    mul-int/2addr v0, v1

    .line 93
    iget-object p0, p0, Ltl/b;->k:Ltl/a;

    .line 94
    .line 95
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    add-int/2addr p0, v0

    .line 100
    return p0
.end method
