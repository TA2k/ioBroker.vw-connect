.class public final Lh3/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh3/e;


# static fields
.field public static final b:Lh3/f;

.field public static final c:Lh3/f;


# instance fields
.field public final synthetic a:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lh3/f;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lh3/f;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lh3/f;->b:Lh3/f;

    .line 8
    .line 9
    new-instance v0, Lh3/f;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lh3/f;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lh3/f;->c:Lh3/f;

    .line 16
    .line 17
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lh3/f;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lh3/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lh3/f;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Lh3/g;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lh3/g;-><init>(Lh3/c;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0}, Landroid/graphics/Bitmap;->createBitmap(Landroid/graphics/Picture;)Landroid/graphics/Bitmap;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :pswitch_0
    iget-wide v0, p1, Lh3/c;->u:J

    .line 17
    .line 18
    const/16 p0, 0x20

    .line 19
    .line 20
    shr-long v2, v0, p0

    .line 21
    .line 22
    long-to-int p0, v2

    .line 23
    const-wide v2, 0xffffffffL

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    and-long/2addr v0, v2

    .line 29
    long-to-int p2, v0

    .line 30
    sget-object v0, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 31
    .line 32
    invoke-static {p0, p2, v0}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    new-instance p2, Landroid/graphics/Canvas;

    .line 37
    .line 38
    invoke-direct {p2, p0}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 39
    .line 40
    .line 41
    sget-object v0, Le3/b;->a:Landroid/graphics/Canvas;

    .line 42
    .line 43
    new-instance v0, Le3/a;

    .line 44
    .line 45
    invoke-direct {v0}, Le3/a;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object p2, v0, Le3/a;->a:Landroid/graphics/Canvas;

    .line 49
    .line 50
    const/4 p2, 0x0

    .line 51
    invoke-virtual {p1, v0, p2}, Lh3/c;->c(Le3/r;Lh3/c;)V

    .line 52
    .line 53
    .line 54
    return-object p0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
