.class public final Lw3/o;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final g:Lw3/o;

.field public static final h:Lw3/o;

.field public static final i:Lw3/o;

.field public static final j:Lw3/o;

.field public static final k:Lw3/o;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lw3/o;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lw3/o;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lw3/o;->g:Lw3/o;

    .line 9
    .line 10
    new-instance v0, Lw3/o;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lw3/o;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lw3/o;->h:Lw3/o;

    .line 17
    .line 18
    new-instance v0, Lw3/o;

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v0, v1, v2}, Lw3/o;-><init>(II)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lw3/o;->i:Lw3/o;

    .line 25
    .line 26
    new-instance v0, Lw3/o;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-direct {v0, v1, v2}, Lw3/o;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Lw3/o;->j:Lw3/o;

    .line 33
    .line 34
    new-instance v0, Lw3/o;

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    invoke-direct {v0, v1, v2}, Lw3/o;-><init>(II)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Lw3/o;->k:Lw3/o;

    .line 41
    .line 42
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lw3/o;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lw3/o;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lw3/h0;->m(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    check-cast p1, Ll2/p1;

    .line 16
    .line 17
    sget-object p0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a:Ll2/e0;

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    invoke-static {p1, p0}, Ll2/b;->q(Ll2/p1;Ll2/s1;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    sget-object p0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 26
    .line 27
    invoke-static {p1, p0}, Ll2/b;->q(Ll2/p1;Ll2/s1;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Landroid/content/Context;

    .line 32
    .line 33
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :pswitch_1
    check-cast p1, Lr3/b;

    .line 39
    .line 40
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    check-cast p1, Lc3/v;

    .line 44
    .line 45
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_3
    check-cast p1, Landroid/content/res/Configuration;

    .line 49
    .line 50
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
