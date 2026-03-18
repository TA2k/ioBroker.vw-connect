.class public final synthetic Lyt/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lyt/g;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lyt/g;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lyt/g;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    .line 1
    iget v0, p0, Lyt/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lyt/g;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lz2/e;

    .line 9
    .line 10
    iget-object p0, p0, Lyt/g;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Landroid/util/LongSparseArray;

    .line 13
    .line 14
    invoke-static {v0, p0}, Lfb/w;->c(Lz2/e;Landroid/util/LongSparseArray;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    iget-object v0, p0, Lyt/g;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Lyt/h;

    .line 21
    .line 22
    iget-object p0, p0, Lyt/g;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lyt/b;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iget-object v1, p0, Lyt/b;->a:Lau/s;

    .line 30
    .line 31
    iget-object p0, p0, Lyt/b;->b:Lau/i;

    .line 32
    .line 33
    invoke-virtual {v0, v1, p0}, Lyt/h;->d(Lau/s;Lau/i;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
