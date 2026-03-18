.class public final Lam0/y;
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
    iput p2, p0, Lam0/y;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lam0/y;->e:Lne0/c;

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
    iget v0, p0, Lam0/y;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lam0/y;->e:Lne0/c;

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
    iget-object p0, p0, Lam0/y;->e:Lne0/c;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_1
    iget-object p0, p0, Lam0/y;->e:Lne0/c;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_2
    iget-object p0, p0, Lam0/y;->e:Lne0/c;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_3
    iget-object p0, p0, Lam0/y;->e:Lne0/c;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_4
    iget-object p0, p0, Lam0/y;->e:Lne0/c;

    .line 28
    .line 29
    iget-object v0, p0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    if-nez v0, :cond_0

    .line 36
    .line 37
    iget-object p0, p0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 38
    .line 39
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    :cond_0
    return-object v0

    .line 44
    :pswitch_5
    iget-object p0, p0, Lam0/y;->e:Lne0/c;

    .line 45
    .line 46
    iget-object p0, p0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 47
    .line 48
    invoke-static {p0}, Llp/od;->a(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_6
    iget-object p0, p0, Lam0/y;->e:Lne0/c;

    .line 54
    .line 55
    return-object p0

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
