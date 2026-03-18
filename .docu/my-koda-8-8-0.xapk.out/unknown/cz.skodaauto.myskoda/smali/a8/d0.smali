.class public final synthetic La8/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Lb8/a;Ljava/util/List;)V
    .locals 0

    .line 1
    const/4 p1, 0x1

    iput p1, p0, La8/d0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, La8/d0;->e:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Lhr/x0;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, La8/d0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/d0;->e:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, La8/d0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lb8/j;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    iget-object p0, p0, La8/d0;->e:Ljava/util/List;

    .line 13
    .line 14
    check-cast p1, Lt7/j0;

    .line 15
    .line 16
    invoke-interface {p1, p0}, Lt7/j0;->t(Ljava/util/List;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
