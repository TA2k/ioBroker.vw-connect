.class public final synthetic Lc2/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/CancellationSignal$OnCancelListener;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc2/i;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lc2/i;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onCancel()V
    .locals 3

    .line 1
    iget v0, p0, Lc2/i;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lc2/i;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lvy0/x1;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, v0}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    check-cast p0, Le2/w0;

    .line 16
    .line 17
    if-eqz p0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Le2/w0;->d:Lt1/p0;

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    sget-wide v1, Lg4/o0;->b:J

    .line 24
    .line 25
    invoke-virtual {v0, v1, v2}, Lt1/p0;->e(J)V

    .line 26
    .line 27
    .line 28
    :cond_0
    iget-object p0, p0, Le2/w0;->d:Lt1/p0;

    .line 29
    .line 30
    if-eqz p0, :cond_1

    .line 31
    .line 32
    sget-wide v0, Lg4/o0;->b:J

    .line 33
    .line 34
    invoke-virtual {p0, v0, v1}, Lt1/p0;->f(J)V

    .line 35
    .line 36
    .line 37
    :cond_1
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
