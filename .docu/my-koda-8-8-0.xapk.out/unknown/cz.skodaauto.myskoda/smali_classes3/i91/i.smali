.class public final synthetic Li91/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li91/l1;


# direct methods
.method public synthetic constructor <init>(Li91/l1;I)V
    .locals 0

    .line 1
    iput p2, p0, Li91/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li91/i;->e:Li91/l1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Li91/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Li91/i;->e:Li91/l1;

    .line 7
    .line 8
    iget v0, p0, Li91/l1;->d:F

    .line 9
    .line 10
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Li91/l1;->i:Ll2/j1;

    .line 17
    .line 18
    iget p0, p0, Li91/l1;->d:F

    .line 19
    .line 20
    new-instance v1, Lt4/f;

    .line 21
    .line 22
    invoke-direct {v1, p0}, Lt4/f;-><init>(F)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget-object p0, p0, Li91/i;->e:Li91/l1;

    .line 32
    .line 33
    invoke-virtual {p0}, Li91/l1;->e()V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
