.class public final synthetic Ll2/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/t;


# direct methods
.method public synthetic constructor <init>(Ll2/t;I)V
    .locals 0

    .line 1
    iput p2, p0, Ll2/p;->d:I

    iput-object p1, p0, Ll2/p;->e:Ll2/t;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ll2/t;Ll2/a1;)V
    .locals 0

    .line 2
    const/4 p2, 0x0

    iput p2, p0, Ll2/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ll2/p;->e:Ll2/t;

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ll2/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ll2/p;->e:Ll2/t;

    .line 7
    .line 8
    invoke-virtual {p0}, Ll2/t;->n()Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Ll2/p;->e:Ll2/t;

    .line 14
    .line 15
    invoke-virtual {p0}, Ll2/t;->n()Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :pswitch_1
    const/4 p0, 0x0

    .line 21
    throw p0

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
