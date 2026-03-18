.class public final Ld7/b;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Ld7/b;

.field public static final h:Ld7/b;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ld7/b;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Ld7/b;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Ld7/b;->g:Ld7/b;

    .line 9
    .line 10
    new-instance v0, Ld7/b;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Ld7/b;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Ld7/b;->h:Ld7/b;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Ld7/b;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Ld7/b;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p2, Ly6/p;

    .line 7
    .line 8
    instance-of p0, p2, Lf7/n;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    move-object p1, p2

    .line 13
    :cond_0
    return-object p1

    .line 14
    :pswitch_0
    check-cast p2, Ly6/p;

    .line 15
    .line 16
    instance-of p0, p2, Lf7/t;

    .line 17
    .line 18
    if-eqz p0, :cond_1

    .line 19
    .line 20
    move-object p1, p2

    .line 21
    :cond_1
    return-object p1

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
