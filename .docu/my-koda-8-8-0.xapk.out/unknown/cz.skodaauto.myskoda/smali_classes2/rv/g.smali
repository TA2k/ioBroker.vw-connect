.class public final Lrv/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j1;


# static fields
.field public static final b:Lrv/g;

.field public static final c:Lrv/g;

.field public static final d:Lrv/g;

.field public static final e:Lrv/g;

.field public static final f:Lrv/g;


# instance fields
.field public final synthetic a:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lrv/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lrv/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lrv/g;->b:Lrv/g;

    .line 8
    .line 9
    new-instance v0, Lrv/g;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lrv/g;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lrv/g;->c:Lrv/g;

    .line 16
    .line 17
    new-instance v0, Lrv/g;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lrv/g;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lrv/g;->d:Lrv/g;

    .line 24
    .line 25
    new-instance v0, Lrv/g;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lrv/g;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lrv/g;->e:Lrv/g;

    .line 32
    .line 33
    new-instance v0, Lrv/g;

    .line 34
    .line 35
    const/4 v1, 0x4

    .line 36
    invoke-direct {v0, v1}, Lrv/g;-><init>(I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lrv/g;->f:Lrv/g;

    .line 40
    .line 41
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lrv/g;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(I)Z
    .locals 1

    .line 1
    iget p0, p0, Lrv/g;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    if-eq p1, p0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x2

    .line 12
    if-eq p1, v0, :cond_0

    .line 13
    .line 14
    const/4 p0, 0x0

    .line 15
    :cond_0
    return p0

    .line 16
    :pswitch_0
    invoke-static {p1}, Lkp/r6;->b(I)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    const/4 p0, 0x0

    .line 25
    :goto_0
    return p0

    .line 26
    :pswitch_1
    invoke-static {p1}, Lkp/q6;->c(I)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eqz p0, :cond_2

    .line 31
    .line 32
    const/4 p0, 0x1

    .line 33
    goto :goto_1

    .line 34
    :cond_2
    const/4 p0, 0x0

    .line 35
    :goto_1
    return p0

    .line 36
    :pswitch_2
    const/4 p0, 0x1

    .line 37
    if-eqz p1, :cond_3

    .line 38
    .line 39
    if-eq p1, p0, :cond_3

    .line 40
    .line 41
    const/4 v0, 0x2

    .line 42
    if-eq p1, v0, :cond_3

    .line 43
    .line 44
    const/4 v0, 0x3

    .line 45
    if-eq p1, v0, :cond_3

    .line 46
    .line 47
    const/4 v0, 0x4

    .line 48
    if-eq p1, v0, :cond_3

    .line 49
    .line 50
    const/4 p0, 0x0

    .line 51
    :cond_3
    return p0

    .line 52
    :pswitch_3
    const/4 p0, 0x1

    .line 53
    if-eqz p1, :cond_4

    .line 54
    .line 55
    if-eq p1, p0, :cond_4

    .line 56
    .line 57
    const/4 v0, 0x2

    .line 58
    if-eq p1, v0, :cond_4

    .line 59
    .line 60
    const/4 p0, 0x0

    .line 61
    :cond_4
    return p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
