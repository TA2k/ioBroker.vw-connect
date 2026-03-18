.class public final Lrt/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkx0/a;


# instance fields
.field public final synthetic d:I

.field public final e:Lcom/google/firebase/messaging/w;


# direct methods
.method public synthetic constructor <init>(Lcom/google/firebase/messaging/w;I)V
    .locals 0

    .line 1
    iput p2, p0, Lrt/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lrt/a;->e:Lcom/google/firebase/messaging/w;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lrt/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lrt/a;->e:Lcom/google/firebase/messaging/w;

    .line 7
    .line 8
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lgt/b;

    .line 11
    .line 12
    invoke-static {p0}, Lkp/s6;->c(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    iget-object p0, p0, Lrt/a;->e:Lcom/google/firebase/messaging/w;

    .line 17
    .line 18
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lsr/f;

    .line 21
    .line 22
    invoke-static {p0}, Lkp/s6;->c(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
