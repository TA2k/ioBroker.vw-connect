.class public final synthetic Lhh/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ldh/u;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ldh/u;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhh/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhh/c;->e:Ldh/u;

    .line 4
    .line 5
    iput-object p2, p0, Lhh/c;->f:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lhh/c;->d:I

    .line 2
    .line 3
    check-cast p1, Lzb/f0;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "it"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lai/e;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    const/16 v2, 0x8

    .line 17
    .line 18
    iget-object v3, p0, Lhh/c;->e:Ldh/u;

    .line 19
    .line 20
    iget-object p0, p0, Lhh/c;->f:Ljava/lang/String;

    .line 21
    .line 22
    invoke-direct {v0, v3, p0, v1, v2}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1, v0}, Lzb/b;->A(Lzb/f0;Lay0/k;)Lyy0/m1;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_0
    const-string v0, "it"

    .line 31
    .line 32
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    new-instance v0, Lai/e;

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    const/4 v2, 0x6

    .line 39
    iget-object v3, p0, Lhh/c;->e:Ldh/u;

    .line 40
    .line 41
    iget-object p0, p0, Lhh/c;->f:Ljava/lang/String;

    .line 42
    .line 43
    invoke-direct {v0, v3, p0, v1, v2}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 44
    .line 45
    .line 46
    invoke-static {p1, v0}, Lzb/b;->A(Lzb/f0;Lay0/k;)Lyy0/m1;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
