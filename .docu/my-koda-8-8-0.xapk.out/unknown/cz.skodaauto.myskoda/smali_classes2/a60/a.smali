.class public final synthetic La60/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lne0/c;


# direct methods
.method public synthetic constructor <init>(Lne0/c;I)V
    .locals 0

    .line 1
    iput p2, p0, La60/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La60/a;->e:Lne0/c;

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
    .locals 1

    .line 1
    iget v0, p0, La60/a;->d:I

    .line 2
    .line 3
    iget-object p0, p0, La60/a;->e:Lne0/c;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 9
    .line 10
    invoke-static {p0}, Llp/od;->a(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 16
    .line 17
    invoke-static {p0}, Llp/od;->a(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :pswitch_1
    return-object p0

    .line 22
    :pswitch_2
    iget-object p0, p0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 23
    .line 24
    invoke-static {p0}, Llp/od;->a(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
