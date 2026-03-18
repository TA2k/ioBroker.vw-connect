.class public final synthetic La0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly4/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:La0/e;


# direct methods
.method public synthetic constructor <init>(La0/e;I)V
    .locals 0

    .line 1
    iput p2, p0, La0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La0/a;->e:La0/e;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final h(Ly4/h;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, La0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, La0/a;->e:La0/e;

    .line 7
    .line 8
    iget-object v0, p0, La0/e;->d:Lj0/h;

    .line 9
    .line 10
    new-instance v1, La0/c;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v1, p0, p1, v2}, La0/c;-><init>(La0/e;Ly4/h;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 17
    .line 18
    .line 19
    const-string p0, "clearCaptureRequestOptions"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_0
    iget-object p0, p0, La0/a;->e:La0/e;

    .line 23
    .line 24
    iget-object v0, p0, La0/e;->d:Lj0/h;

    .line 25
    .line 26
    new-instance v1, La0/c;

    .line 27
    .line 28
    const/4 v2, 0x1

    .line 29
    invoke-direct {v1, p0, p1, v2}, La0/c;-><init>(La0/e;Ly4/h;I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 33
    .line 34
    .line 35
    const-string p0, "addCaptureRequestOptions"

    .line 36
    .line 37
    return-object p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
