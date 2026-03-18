.class public Lwq/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lao/a;
.implements Lgs/e;
.implements Lp/a;
.implements Ll9/h;
.implements Llp/jg;
.implements Lsl/e;
.implements Lvp/u;
.implements Lvs/a;
.implements Lzo/c;


# static fields
.field public static final synthetic e:Lwq/f;

.field public static final synthetic f:Lwq/f;

.field public static final synthetic g:Lwq/f;

.field public static final synthetic h:Lwq/f;

.field public static final synthetic i:Lwq/f;

.field public static final synthetic j:Lwq/f;

.field public static final synthetic k:Lwq/f;

.field public static final synthetic l:Lwq/f;

.field public static final synthetic m:Lwq/f;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lwq/f;

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lwq/f;->e:Lwq/f;

    .line 9
    .line 10
    new-instance v0, Lwq/f;

    .line 11
    .line 12
    const/16 v1, 0x10

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lwq/f;->f:Lwq/f;

    .line 18
    .line 19
    new-instance v0, Lwq/f;

    .line 20
    .line 21
    const/16 v1, 0x11

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lwq/f;->g:Lwq/f;

    .line 27
    .line 28
    new-instance v0, Lwq/f;

    .line 29
    .line 30
    const/16 v1, 0x12

    .line 31
    .line 32
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lwq/f;->h:Lwq/f;

    .line 36
    .line 37
    new-instance v0, Lwq/f;

    .line 38
    .line 39
    const/16 v1, 0x13

    .line 40
    .line 41
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lwq/f;->i:Lwq/f;

    .line 45
    .line 46
    new-instance v0, Lwq/f;

    .line 47
    .line 48
    const/16 v1, 0x14

    .line 49
    .line 50
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lwq/f;->j:Lwq/f;

    .line 54
    .line 55
    new-instance v0, Lwq/f;

    .line 56
    .line 57
    const/16 v1, 0x15

    .line 58
    .line 59
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 60
    .line 61
    .line 62
    sput-object v0, Lwq/f;->k:Lwq/f;

    .line 63
    .line 64
    new-instance v0, Lwq/f;

    .line 65
    .line 66
    const/16 v1, 0x16

    .line 67
    .line 68
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Lwq/f;->l:Lwq/f;

    .line 72
    .line 73
    new-instance v0, Lwq/f;

    .line 74
    .line 75
    const/16 v1, 0x17

    .line 76
    .line 77
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Lwq/f;->m:Lwq/f;

    .line 81
    .line 82
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lwq/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lt0/c;)V
    .locals 1

    const/16 p2, 0x19

    iput p2, p0, Lwq/f;->d:I

    const-string p2, "context"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-static {p1}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    move-result-object p2

    invoke-virtual {p2}, Landroid/view/ViewConfiguration;->getScaledTouchSlop()I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    new-instance p2, Landroid/view/GestureDetector;

    .line 5
    new-instance v0, Lx0/a;

    invoke-direct {v0, p0}, Lx0/a;-><init>(Lwq/f;)V

    .line 6
    invoke-direct {p2, p1, v0}, Landroid/view/GestureDetector;-><init>(Landroid/content/Context;Landroid/view/GestureDetector$OnGestureListener;)V

    return-void
.end method

.method public static b(Ljava/util/List;)Ljava/util/ArrayList;
    .locals 4

    .line 1
    const-string v0, "protocols"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p0, Ljava/lang/Iterable;

    .line 7
    .line 8
    new-instance v0, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    move-object v2, v1

    .line 28
    check-cast v2, Ld01/i0;

    .line 29
    .line 30
    sget-object v3, Ld01/i0;->f:Ld01/i0;

    .line 31
    .line 32
    if-eq v2, v3, :cond_0

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    new-instance p0, Ljava/util/ArrayList;

    .line 39
    .line 40
    const/16 v1, 0xa

    .line 41
    .line 42
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    invoke-direct {p0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-eqz v1, :cond_2

    .line 58
    .line 59
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    check-cast v1, Ld01/i0;

    .line 64
    .line 65
    iget-object v1, v1, Ld01/i0;->d:Ljava/lang/String;

    .line 66
    .line 67
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    return-object p0
.end method

.method public static c(Ljava/util/List;)[B
    .locals 3

    .line 1
    const-string v0, "protocols"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lu01/f;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-static {p0}, Lwq/f;->b(Ljava/util/List;)Ljava/util/ArrayList;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    check-cast v1, Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    invoke-virtual {v0, v2}, Lu01/f;->h0(I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v1}, Lu01/f;->x0(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    iget-wide v1, v0, Lu01/f;->e:J

    .line 43
    .line 44
    invoke-virtual {v0, v1, v2}, Lu01/f;->q(J)[B

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

.method public static k()Ljava/util/List;
    .locals 6

    .line 1
    sget-object v0, Lhp0/d;->g:Lhp0/d;

    .line 2
    .line 3
    sget-object v1, Lhp0/d;->f:Lhp0/d;

    .line 4
    .line 5
    sget-object v2, Lhp0/d;->h:Lhp0/d;

    .line 6
    .line 7
    sget-object v3, Lhp0/d;->j:Lhp0/d;

    .line 8
    .line 9
    sget-object v4, Lhp0/d;->i:Lhp0/d;

    .line 10
    .line 11
    sget-object v5, Lhp0/d;->k:Lhp0/d;

    .line 12
    .line 13
    filled-new-array/range {v0 .. v5}, [Lhp0/d;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    return-object v0
.end method

.method public static l(Lwq/f;Lhy0/d;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string p0, "kClass"

    .line 5
    .line 6
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public static m(Ljava/lang/String;)Ljava/time/LocalTime;
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-static {p0}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return-object p0
.end method

.method public static n(Ljava/time/LocalTime;)Ljava/lang/String;
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    sget-object v0, Ljava/time/format/DateTimeFormatter;->ISO_LOCAL_TIME:Ljava/time/format/DateTimeFormatter;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/time/LocalTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method


# virtual methods
.method public a()J
    .locals 2

    .line 1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    return-object p1
.end method

.method public d()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p0, Lfv/b;

    .line 2
    .line 3
    const-class v0, Lfv/a;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lfv/a;

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    invoke-direct {p0, p1}, Lfv/b;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public f(Lt7/o;)Ll9/j;
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    const-string p1, "This SubtitleParser.Factory doesn\'t support any formats."

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Llp/e8;

    .line 2
    .line 3
    iget-object p0, p1, Llp/e8;->e:Llp/y1;

    .line 4
    .line 5
    iget-object v0, p1, Llp/e8;->j:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {p0}, Lpv/b;->b(Llp/y1;)Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    new-instance v1, Lov/b;

    .line 12
    .line 13
    iget-object v2, p1, Llp/e8;->h:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v2}, Lm20/k;->b(Ljava/lang/String;)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    const-string v2, ""

    .line 22
    .line 23
    :cond_0
    invoke-static {p0}, Lpv/b;->a(Ljava/util/List;)Landroid/graphics/Rect;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-static {v0}, Lm20/k;->b(Ljava/lang/String;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_1

    .line 32
    .line 33
    const-string v0, "und"

    .line 34
    .line 35
    :cond_1
    iget-object v4, p1, Llp/e8;->d:[Llp/yd;

    .line 36
    .line 37
    invoke-static {v4}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    new-instance v5, Ldv/a;

    .line 42
    .line 43
    const/16 v6, 0xc

    .line 44
    .line 45
    invoke-direct {v5, v6}, Ldv/a;-><init>(I)V

    .line 46
    .line 47
    .line 48
    invoke-static {v4, v5}, Llp/cg;->d(Ljava/util/List;Llp/jg;)Ljava/util/AbstractList;

    .line 49
    .line 50
    .line 51
    iget-object p1, p1, Llp/e8;->e:Llp/y1;

    .line 52
    .line 53
    iget p1, p1, Llp/y1;->h:F

    .line 54
    .line 55
    invoke-direct {v1, v2, v3, p0, v0}, Lh/w;-><init>(Ljava/lang/String;Landroid/graphics/Rect;Ljava/util/List;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    return-object v1
.end method

.method public h()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lwq/f;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 7
    .line 8
    sget-object p0, Lcom/google/android/gms/internal/measurement/u8;->e:Lcom/google/android/gms/internal/measurement/u8;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/u8;->b()Lcom/google/android/gms/internal/measurement/v8;

    .line 11
    .line 12
    .line 13
    sget-object p0, Lcom/google/android/gms/internal/measurement/w8;->e:Lcom/google/android/gms/internal/measurement/n4;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Boolean;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_0
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 26
    .line 27
    sget-object p0, Lcom/google/android/gms/internal/measurement/s9;->e:Lcom/google/android/gms/internal/measurement/s9;

    .line 28
    .line 29
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/s9;->d:Lgr/p;

    .line 30
    .line 31
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Lcom/google/android/gms/internal/measurement/t9;

    .line 34
    .line 35
    sget-object p0, Lcom/google/android/gms/internal/measurement/u9;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 36
    .line 37
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Ljava/lang/Boolean;

    .line 42
    .line 43
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_1
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 48
    .line 49
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 52
    .line 53
    .line 54
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->Z:Lcom/google/android/gms/internal/measurement/n4;

    .line 55
    .line 56
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    check-cast p0, Ljava/lang/Long;

    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_2
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 67
    .line 68
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 69
    .line 70
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 71
    .line 72
    .line 73
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->e0:Lcom/google/android/gms/internal/measurement/n4;

    .line 74
    .line 75
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Ljava/lang/Long;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_3
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 86
    .line 87
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 88
    .line 89
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 90
    .line 91
    .line 92
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->H:Lcom/google/android/gms/internal/measurement/n4;

    .line 93
    .line 94
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    check-cast p0, Ljava/lang/Long;

    .line 99
    .line 100
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    return-object p0

    .line 104
    :pswitch_4
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 105
    .line 106
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 107
    .line 108
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 109
    .line 110
    .line 111
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->z:Lcom/google/android/gms/internal/measurement/n4;

    .line 112
    .line 113
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    check-cast p0, Ljava/lang/Long;

    .line 118
    .line 119
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 120
    .line 121
    .line 122
    return-object p0

    .line 123
    :pswitch_5
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 124
    .line 125
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 126
    .line 127
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 128
    .line 129
    .line 130
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->K:Lcom/google/android/gms/internal/measurement/n4;

    .line 131
    .line 132
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    check-cast p0, Ljava/lang/Long;

    .line 137
    .line 138
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 139
    .line 140
    .line 141
    move-result-wide v0

    .line 142
    long-to-int p0, v0

    .line 143
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0

    .line 148
    :pswitch_6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 149
    .line 150
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 151
    .line 152
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 153
    .line 154
    .line 155
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->o0:Lcom/google/android/gms/internal/measurement/n4;

    .line 156
    .line 157
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    check-cast p0, Ljava/lang/Long;

    .line 162
    .line 163
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 164
    .line 165
    .line 166
    move-result-wide v0

    .line 167
    long-to-int p0, v0

    .line 168
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    return-object p0

    .line 173
    :pswitch_7
    sget-object p0, Lcom/google/android/gms/internal/measurement/n7;->e:Lcom/google/android/gms/internal/measurement/n7;

    .line 174
    .line 175
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/n7;->d:Lgr/p;

    .line 176
    .line 177
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast p0, Lcom/google/android/gms/internal/measurement/o7;

    .line 180
    .line 181
    sget-object p0, Lcom/google/android/gms/internal/measurement/p7;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 182
    .line 183
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    check-cast p0, Ljava/lang/Boolean;

    .line 188
    .line 189
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 190
    .line 191
    .line 192
    move-result p0

    .line 193
    new-instance v0, Ljava/lang/Boolean;

    .line 194
    .line 195
    invoke-direct {v0, p0}, Ljava/lang/Boolean;-><init>(Z)V

    .line 196
    .line 197
    .line 198
    return-object v0

    .line 199
    :pswitch_data_0
    .packed-switch 0xf
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

.method public i(Lt7/o;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public j(Lt7/o;)I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public o([Ljava/lang/StackTraceElement;)[Ljava/lang/StackTraceElement;
    .locals 13

    .line 1
    new-instance p0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    array-length v0, p1

    .line 7
    new-array v0, v0, [Ljava/lang/StackTraceElement;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const/4 v2, 0x1

    .line 11
    move v3, v1

    .line 12
    move v4, v3

    .line 13
    move v5, v2

    .line 14
    :goto_0
    array-length v6, p1

    .line 15
    if-ge v3, v6, :cond_5

    .line 16
    .line 17
    aget-object v6, p1, v3

    .line 18
    .line 19
    invoke-virtual {p0, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v7

    .line 23
    check-cast v7, Ljava/lang/Integer;

    .line 24
    .line 25
    if-eqz v7, :cond_4

    .line 26
    .line 27
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 28
    .line 29
    .line 30
    move-result v8

    .line 31
    sub-int v9, v3, v8

    .line 32
    .line 33
    add-int v10, v3, v9

    .line 34
    .line 35
    array-length v11, p1

    .line 36
    if-le v10, v11, :cond_0

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_0
    move v10, v1

    .line 40
    :goto_1
    if-ge v10, v9, :cond_2

    .line 41
    .line 42
    add-int v11, v8, v10

    .line 43
    .line 44
    aget-object v11, p1, v11

    .line 45
    .line 46
    add-int v12, v3, v10

    .line 47
    .line 48
    aget-object v12, p1, v12

    .line 49
    .line 50
    invoke-virtual {v11, v12}, Ljava/lang/StackTraceElement;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v11

    .line 54
    if-nez v11, :cond_1

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_1
    add-int/lit8 v10, v10, 0x1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 61
    .line 62
    .line 63
    move-result v7

    .line 64
    sub-int v7, v3, v7

    .line 65
    .line 66
    const/16 v8, 0xa

    .line 67
    .line 68
    if-ge v5, v8, :cond_3

    .line 69
    .line 70
    invoke-static {p1, v3, v0, v4, v7}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 71
    .line 72
    .line 73
    add-int/2addr v4, v7

    .line 74
    add-int/lit8 v5, v5, 0x1

    .line 75
    .line 76
    :cond_3
    add-int/lit8 v7, v7, -0x1

    .line 77
    .line 78
    add-int/2addr v7, v3

    .line 79
    goto :goto_3

    .line 80
    :cond_4
    :goto_2
    aget-object v5, p1, v3

    .line 81
    .line 82
    aput-object v5, v0, v4

    .line 83
    .line 84
    add-int/lit8 v4, v4, 0x1

    .line 85
    .line 86
    move v5, v2

    .line 87
    move v7, v3

    .line 88
    :goto_3
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    invoke-virtual {p0, v6, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    add-int/lit8 v3, v7, 0x1

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_5
    new-array p0, v4, [Ljava/lang/StackTraceElement;

    .line 99
    .line 100
    invoke-static {v0, v1, p0, v1, v4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 101
    .line 102
    .line 103
    array-length v0, p1

    .line 104
    if-ge v4, v0, :cond_6

    .line 105
    .line 106
    return-object p0

    .line 107
    :cond_6
    return-object p1
.end method

.method public p(Landroid/content/Context;Ljava/lang/String;Lzo/b;)Lm8/j;
    .locals 3

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
    const/4 v1, 0x1

    .line 13
    const/4 v2, 0x0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-interface {p3, p1, p2, v2}, Lzo/b;->b(Landroid/content/Context;Ljava/lang/String;Z)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    iput p1, p0, Lm8/j;->b:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-interface {p3, p1, p2, v1}, Lzo/b;->b(Landroid/content/Context;Ljava/lang/String;Z)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    iput p1, p0, Lm8/j;->b:I

    .line 28
    .line 29
    :goto_0
    iget p2, p0, Lm8/j;->a:I

    .line 30
    .line 31
    if-nez p2, :cond_1

    .line 32
    .line 33
    if-nez p1, :cond_2

    .line 34
    .line 35
    move v1, v2

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v2, p2

    .line 38
    :cond_2
    if-lt v2, p1, :cond_3

    .line 39
    .line 40
    const/4 v1, -0x1

    .line 41
    :cond_3
    :goto_1
    iput v1, p0, Lm8/j;->c:I

    .line 42
    .line 43
    return-object p0
.end method

.method public shutdown()V
    .locals 0

    .line 1
    return-void
.end method
