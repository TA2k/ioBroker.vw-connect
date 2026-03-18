.class public final Lky0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lky0/j;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/n;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lky0/m;->a:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    check-cast p1, Lrx0/h;

    iput-object p1, p0, Lky0/m;->b:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lky0/m;->a:I

    iput-object p1, p0, Lky0/m;->b:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 2

    .line 1
    iget v0, p0, Lky0/m;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lky0/m;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/lang/Iterable;

    .line 9
    .line 10
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lky0/m;->b:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, [B

    .line 18
    .line 19
    new-instance v0, Lkotlin/jvm/internal/b;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, v1, p0}, Lkotlin/jvm/internal/b;-><init>(I[B)V

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    :pswitch_1
    iget-object p0, p0, Lky0/m;->b:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, [Ljava/lang/Object;

    .line 29
    .line 30
    invoke-static {p0}, Lkotlin/jvm/internal/m;->j([Ljava/lang/Object;)Landroidx/collection/d1;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_2
    new-instance v0, Lly0/h;

    .line 36
    .line 37
    iget-object p0, p0, Lky0/m;->b:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Ljava/lang/CharSequence;

    .line 40
    .line 41
    invoke-direct {v0, p0}, Lly0/h;-><init>(Ljava/lang/CharSequence;)V

    .line 42
    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_3
    iget-object p0, p0, Lky0/m;->b:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Ljava/util/Iterator;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_4
    iget-object p0, p0, Lky0/m;->b:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p0, Lrx0/h;

    .line 53
    .line 54
    invoke-static {p0}, Llp/ke;->a(Lay0/n;)Lky0/k;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
