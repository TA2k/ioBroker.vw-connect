.class public final Lyy0/w1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/v1;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lyy0/w1;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lzy0/w;)Lyy0/i;
    .locals 2

    .line 1
    iget p0, p0, Lyy0/w1;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Lwp0/c;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/16 v1, 0x1d

    .line 10
    .line 11
    invoke-direct {p0, p1, v0, v1}, Lwp0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    new-instance p1, Lyy0/m1;

    .line 15
    .line 16
    invoke-direct {p1, p0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 17
    .line 18
    .line 19
    return-object p1

    .line 20
    :pswitch_0
    sget-object p0, Lyy0/s1;->d:Lyy0/s1;

    .line 21
    .line 22
    new-instance p1, Lyy0/m;

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    invoke-direct {p1, p0, v0}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 26
    .line 27
    .line 28
    return-object p1

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lyy0/w1;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "SharingStarted.Lazily"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "SharingStarted.Eagerly"

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
