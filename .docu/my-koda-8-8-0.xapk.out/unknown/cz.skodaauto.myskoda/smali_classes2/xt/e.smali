.class public final synthetic Lxt/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxt/f;

.field public final synthetic f:Lzt/h;


# direct methods
.method public synthetic constructor <init>(Lxt/f;Lzt/h;I)V
    .locals 0

    .line 1
    iput p3, p0, Lxt/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxt/e;->e:Lxt/f;

    .line 4
    .line 5
    iput-object p2, p0, Lxt/e;->f:Lzt/h;

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
    .locals 1

    .line 1
    iget v0, p0, Lxt/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxt/e;->f:Lzt/h;

    .line 7
    .line 8
    iget-object p0, p0, Lxt/e;->e:Lxt/f;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lxt/f;->b(Lzt/h;)Lau/d;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lxt/f;->b:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;->add(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void

    .line 22
    :pswitch_0
    iget-object v0, p0, Lxt/e;->f:Lzt/h;

    .line 23
    .line 24
    iget-object p0, p0, Lxt/e;->e:Lxt/f;

    .line 25
    .line 26
    invoke-virtual {p0, v0}, Lxt/f;->b(Lzt/h;)Lau/d;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    iget-object p0, p0, Lxt/f;->b:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;->add(Ljava/lang/Object;)Z

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
