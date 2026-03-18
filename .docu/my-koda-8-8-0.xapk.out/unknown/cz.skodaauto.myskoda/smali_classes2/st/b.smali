.class public final Lst/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgs/e;
.implements Laq/i;
.implements Lo8/q;
.implements Lrr/b;
.implements Lvp/u;
.implements Ldt/a;
.implements Lzo/c;


# static fields
.field public static e:Lst/b;

.field public static volatile f:Lst/b;

.field public static final synthetic g:Lst/b;

.field public static final synthetic h:Lst/b;

.field public static final synthetic i:Lst/b;

.field public static final synthetic j:Lst/b;

.field public static final synthetic k:Lst/b;

.field public static final synthetic l:Lst/b;

.field public static final synthetic m:Lst/b;

.field public static final synthetic n:Lst/b;

.field public static final synthetic o:Lst/b;

.field public static final synthetic p:Lst/b;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lst/b;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lst/b;->g:Lst/b;

    .line 9
    .line 10
    new-instance v0, Lst/b;

    .line 11
    .line 12
    const/16 v1, 0x11

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lst/b;->h:Lst/b;

    .line 18
    .line 19
    new-instance v0, Lst/b;

    .line 20
    .line 21
    const/16 v1, 0x12

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lst/b;->i:Lst/b;

    .line 27
    .line 28
    new-instance v0, Lst/b;

    .line 29
    .line 30
    const/16 v1, 0x13

    .line 31
    .line 32
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lst/b;->j:Lst/b;

    .line 36
    .line 37
    new-instance v0, Lst/b;

    .line 38
    .line 39
    const/16 v1, 0x14

    .line 40
    .line 41
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lst/b;->k:Lst/b;

    .line 45
    .line 46
    new-instance v0, Lst/b;

    .line 47
    .line 48
    const/16 v1, 0x15

    .line 49
    .line 50
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lst/b;->l:Lst/b;

    .line 54
    .line 55
    new-instance v0, Lst/b;

    .line 56
    .line 57
    const/16 v1, 0x16

    .line 58
    .line 59
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 60
    .line 61
    .line 62
    sput-object v0, Lst/b;->m:Lst/b;

    .line 63
    .line 64
    new-instance v0, Lst/b;

    .line 65
    .line 66
    const/16 v1, 0x17

    .line 67
    .line 68
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Lst/b;->n:Lst/b;

    .line 72
    .line 73
    new-instance v0, Lst/b;

    .line 74
    .line 75
    const/16 v1, 0x18

    .line 76
    .line 77
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Lst/b;->o:Lst/b;

    .line 81
    .line 82
    new-instance v0, Lst/b;

    .line 83
    .line 84
    const/16 v1, 0x19

    .line 85
    .line 86
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 87
    .line 88
    .line 89
    sput-object v0, Lst/b;->p:Lst/b;

    .line 90
    .line 91
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lst/b;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static final a(F[F[F)F
    .locals 7

    .line 1
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p0}, Ljava/lang/Math;->signum(F)F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-static {p1, v0}, Ljava/util/Arrays;->binarySearch([FF)I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-ltz v2, :cond_0

    .line 14
    .line 15
    aget p0, p2, v2

    .line 16
    .line 17
    mul-float/2addr v1, p0

    .line 18
    return v1

    .line 19
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 20
    .line 21
    neg-int v2, v2

    .line 22
    add-int/lit8 v3, v2, -0x1

    .line 23
    .line 24
    array-length v4, p1

    .line 25
    add-int/lit8 v4, v4, -0x1

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    if-lt v3, v4, :cond_2

    .line 29
    .line 30
    array-length v0, p1

    .line 31
    add-int/lit8 v0, v0, -0x1

    .line 32
    .line 33
    aget v0, p1, v0

    .line 34
    .line 35
    array-length p1, p1

    .line 36
    add-int/lit8 p1, p1, -0x1

    .line 37
    .line 38
    aget p1, p2, p1

    .line 39
    .line 40
    cmpg-float p2, v0, v5

    .line 41
    .line 42
    if-nez p2, :cond_1

    .line 43
    .line 44
    return v5

    .line 45
    :cond_1
    div-float/2addr p1, v0

    .line 46
    mul-float/2addr p1, p0

    .line 47
    return p1

    .line 48
    :cond_2
    const/4 p0, -0x1

    .line 49
    if-ne v3, p0, :cond_3

    .line 50
    .line 51
    const/4 p0, 0x0

    .line 52
    aget p1, p1, p0

    .line 53
    .line 54
    aget p0, p2, p0

    .line 55
    .line 56
    move p2, p1

    .line 57
    move p1, v5

    .line 58
    move v3, p1

    .line 59
    goto :goto_0

    .line 60
    :cond_3
    aget p0, p1, v3

    .line 61
    .line 62
    aget p1, p1, v2

    .line 63
    .line 64
    aget v3, p2, v3

    .line 65
    .line 66
    aget p2, p2, v2

    .line 67
    .line 68
    move v6, p1

    .line 69
    move p1, p0

    .line 70
    move p0, p2

    .line 71
    move p2, v6

    .line 72
    :goto_0
    cmpg-float v2, p1, p2

    .line 73
    .line 74
    if-nez v2, :cond_4

    .line 75
    .line 76
    move v0, v5

    .line 77
    goto :goto_1

    .line 78
    :cond_4
    sub-float/2addr v0, p1

    .line 79
    sub-float/2addr p2, p1

    .line 80
    div-float/2addr v0, p2

    .line 81
    :goto_1
    const/high16 p1, 0x3f800000    # 1.0f

    .line 82
    .line 83
    invoke-static {p1, v0}, Ljava/lang/Math;->min(FF)F

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    invoke-static {v5, p1}, Ljava/lang/Math;->max(FF)F

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    sub-float/2addr p0, v3

    .line 92
    mul-float/2addr p0, p1

    .line 93
    add-float/2addr p0, v3

    .line 94
    mul-float/2addr p0, v1

    .line 95
    return p0
.end method

.method public static d(Landroidx/lifecycle/i1;Landroidx/lifecycle/e1;I)Landroidx/lifecycle/g1;
    .locals 1

    .line 1
    and-int/lit8 p2, p2, 0x2

    .line 2
    .line 3
    if-eqz p2, :cond_1

    .line 4
    .line 5
    instance-of p1, p0, Landroidx/lifecycle/k;

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    move-object p1, p0

    .line 10
    check-cast p1, Landroidx/lifecycle/k;

    .line 11
    .line 12
    invoke-interface {p1}, Landroidx/lifecycle/k;->getDefaultViewModelProviderFactory()Landroidx/lifecycle/e1;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    sget-object p1, Lr7/b;->a:Lr7/b;

    .line 18
    .line 19
    :cond_1
    :goto_0
    instance-of p2, p0, Landroidx/lifecycle/k;

    .line 20
    .line 21
    if-eqz p2, :cond_2

    .line 22
    .line 23
    move-object p2, p0

    .line 24
    check-cast p2, Landroidx/lifecycle/k;

    .line 25
    .line 26
    invoke-interface {p2}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 27
    .line 28
    .line 29
    move-result-object p2

    .line 30
    goto :goto_1

    .line 31
    :cond_2
    sget-object p2, Lp7/a;->b:Lp7/a;

    .line 32
    .line 33
    :goto_1
    const-string v0, "factory"

    .line 34
    .line 35
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string v0, "extras"

    .line 39
    .line 40
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    new-instance v0, Landroidx/lifecycle/g1;

    .line 44
    .line 45
    invoke-interface {p0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-direct {v0, p0, p1, p2}, Landroidx/lifecycle/g1;-><init>(Landroidx/lifecycle/h1;Landroidx/lifecycle/e1;Lp7/c;)V

    .line 50
    .line 51
    .line 52
    return-object v0
.end method

.method public static f(Lhr/h0;J)[B
    .locals 3

    .line 1
    new-instance v0, Lj9/d;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, Lj9/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-virtual {v0, v2}, Lj9/d;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Landroid/os/Bundle;

    .line 35
    .line 36
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    new-instance p0, Landroid/os/Bundle;

    .line 41
    .line 42
    invoke-direct {p0}, Landroid/os/Bundle;-><init>()V

    .line 43
    .line 44
    .line 45
    const-string v0, "c"

    .line 46
    .line 47
    invoke-virtual {p0, v0, v1}, Landroid/os/Bundle;->putParcelableArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 48
    .line 49
    .line 50
    const-string v0, "d"

    .line 51
    .line 52
    invoke-virtual {p0, v0, p1, p2}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 53
    .line 54
    .line 55
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeBundle(Landroid/os/Bundle;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p1}, Landroid/os/Parcel;->marshall()[B

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-virtual {p1}, Landroid/os/Parcel;->recycle()V

    .line 67
    .line 68
    .line 69
    return-object p0
.end method

.method public static final i()Z
    .locals 2

    .line 1
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    return v0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    return v0
.end method


# virtual methods
.method public b(Ljava/lang/String;Ljava/security/Provider;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    invoke-static {p1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    invoke-static {p1, p2}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;Ljava/security/Provider;)Ljavax/crypto/Cipher;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public c(Lo8/c0;)V
    .locals 0

    .line 1
    return-void
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p0, Lfv/d;

    .line 2
    .line 3
    const-class v0, Lfv/g;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Lin/z1;->f(Ljava/lang/Class;)Lgt/b;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-direct {p0, p1}, Lfv/d;-><init>(Lgt/b;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public g(Ljava/lang/Object;)Laq/t;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Void;

    .line 2
    .line 3
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public h()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lst/b;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lcom/google/android/gms/internal/measurement/j9;->e:Lcom/google/android/gms/internal/measurement/j9;

    .line 7
    .line 8
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/j9;->d:Lgr/p;

    .line 9
    .line 10
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lcom/google/android/gms/internal/measurement/k9;

    .line 13
    .line 14
    sget-object p0, Lcom/google/android/gms/internal/measurement/l9;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 15
    .line 16
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Ljava/lang/Boolean;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    new-instance v0, Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-direct {v0, p0}, Ljava/lang/Boolean;-><init>(Z)V

    .line 29
    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_0
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 33
    .line 34
    sget-object p0, Lcom/google/android/gms/internal/measurement/u8;->e:Lcom/google/android/gms/internal/measurement/u8;

    .line 35
    .line 36
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/u8;->b()Lcom/google/android/gms/internal/measurement/v8;

    .line 37
    .line 38
    .line 39
    sget-object p0, Lcom/google/android/gms/internal/measurement/w8;->g:Lcom/google/android/gms/internal/measurement/n4;

    .line 40
    .line 41
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    check-cast p0, Ljava/lang/Boolean;

    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_1
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 52
    .line 53
    sget-object p0, Lcom/google/android/gms/internal/measurement/z7;->e:Lcom/google/android/gms/internal/measurement/z7;

    .line 54
    .line 55
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/z7;->d:Lgr/p;

    .line 56
    .line 57
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Lcom/google/android/gms/internal/measurement/a8;

    .line 60
    .line 61
    sget-object p0, Lcom/google/android/gms/internal/measurement/b8;->c:Lcom/google/android/gms/internal/measurement/n4;

    .line 62
    .line 63
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    check-cast p0, Ljava/lang/Boolean;

    .line 68
    .line 69
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    return-object p0

    .line 73
    :pswitch_2
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 74
    .line 75
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 76
    .line 77
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 78
    .line 79
    .line 80
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->b0:Lcom/google/android/gms/internal/measurement/n4;

    .line 81
    .line 82
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    check-cast p0, Ljava/lang/String;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_3
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 90
    .line 91
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 92
    .line 93
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 94
    .line 95
    .line 96
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->d:Lcom/google/android/gms/internal/measurement/n4;

    .line 97
    .line 98
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    check-cast p0, Ljava/lang/Long;

    .line 103
    .line 104
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 105
    .line 106
    .line 107
    move-result-wide v0

    .line 108
    long-to-int p0, v0

    .line 109
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0

    .line 114
    :pswitch_4
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 115
    .line 116
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 117
    .line 118
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 119
    .line 120
    .line 121
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->t:Lcom/google/android/gms/internal/measurement/n4;

    .line 122
    .line 123
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    check-cast p0, Ljava/lang/Long;

    .line 128
    .line 129
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 130
    .line 131
    .line 132
    move-result-wide v0

    .line 133
    long-to-int p0, v0

    .line 134
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    return-object p0

    .line 139
    :pswitch_5
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 140
    .line 141
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 142
    .line 143
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 144
    .line 145
    .line 146
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->E:Lcom/google/android/gms/internal/measurement/n4;

    .line 147
    .line 148
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    check-cast p0, Ljava/lang/Long;

    .line 153
    .line 154
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 155
    .line 156
    .line 157
    return-object p0

    .line 158
    :pswitch_6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 159
    .line 160
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 161
    .line 162
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 163
    .line 164
    .line 165
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->J:Lcom/google/android/gms/internal/measurement/n4;

    .line 166
    .line 167
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    check-cast p0, Ljava/lang/Long;

    .line 172
    .line 173
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    return-object p0

    .line 177
    :pswitch_7
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 178
    .line 179
    sget-object p0, Lcom/google/android/gms/internal/measurement/e7;->e:Lcom/google/android/gms/internal/measurement/e7;

    .line 180
    .line 181
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e7;->d:Lgr/p;

    .line 182
    .line 183
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast p0, Lcom/google/android/gms/internal/measurement/f7;

    .line 186
    .line 187
    sget-object p0, Lcom/google/android/gms/internal/measurement/g7;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 188
    .line 189
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    check-cast p0, Ljava/lang/Boolean;

    .line 194
    .line 195
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 196
    .line 197
    .line 198
    return-object p0

    .line 199
    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public m()V
    .locals 0

    .line 1
    return-void
.end method

.method public p(Landroid/content/Context;Ljava/lang/String;Lzo/b;)Lm8/j;
    .locals 1

    .line 1
    new-instance p0, Lm8/j;

    .line 2
    .line 3
    invoke-direct {p0}, Lm8/j;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p3, p1, p2}, Lzo/b;->d(Landroid/content/Context;Ljava/lang/String;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iput v0, p0, Lm8/j;->a:I

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    const/4 p1, -0x1

    .line 15
    iput p1, p0, Lm8/j;->c:I

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    const/4 v0, 0x1

    .line 19
    invoke-interface {p3, p1, p2, v0}, Lzo/b;->b(Landroid/content/Context;Ljava/lang/String;Z)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    iput p1, p0, Lm8/j;->b:I

    .line 24
    .line 25
    if-eqz p1, :cond_1

    .line 26
    .line 27
    iput v0, p0, Lm8/j;->c:I

    .line 28
    .line 29
    :cond_1
    return-object p0
.end method

.method public q(II)Lo8/i0;
    .locals 0

    .line 1
    new-instance p0, Lo8/n;

    .line 2
    .line 3
    invoke-direct {p0}, Lo8/n;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
