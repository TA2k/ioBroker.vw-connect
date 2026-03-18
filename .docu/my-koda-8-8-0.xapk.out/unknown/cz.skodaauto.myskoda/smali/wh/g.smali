.class public final synthetic Lwh/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Integer;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Integer;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lwh/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lwh/g;->e:Ljava/lang/Integer;

    .line 4
    .line 5
    iput-object p2, p0, Lwh/g;->f:Lay0/k;

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
    .locals 1

    .line 1
    iget v0, p0, Lwh/g;->d:I

    .line 2
    .line 3
    check-cast p1, Lhi/a;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$sdkViewModel"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance p1, Lyh/e;

    .line 14
    .line 15
    iget-object v0, p0, Lwh/g;->e:Ljava/lang/Integer;

    .line 16
    .line 17
    iget-object p0, p0, Lwh/g;->f:Lay0/k;

    .line 18
    .line 19
    invoke-direct {p1, v0, p0}, Lyh/e;-><init>(Ljava/lang/Integer;Lay0/k;)V

    .line 20
    .line 21
    .line 22
    return-object p1

    .line 23
    :pswitch_0
    const-string v0, "$this$sdkViewModel"

    .line 24
    .line 25
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    new-instance p1, Lwh/h;

    .line 29
    .line 30
    iget-object v0, p0, Lwh/g;->e:Ljava/lang/Integer;

    .line 31
    .line 32
    iget-object p0, p0, Lwh/g;->f:Lay0/k;

    .line 33
    .line 34
    invoke-direct {p1, v0, p0}, Lwh/h;-><init>(Ljava/lang/Integer;Lay0/k;)V

    .line 35
    .line 36
    .line 37
    return-object p1

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
