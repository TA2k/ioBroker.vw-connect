.class public final Lwt0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/l;


# direct methods
.method public synthetic constructor <init>(Lvy0/l;I)V
    .locals 0

    .line 1
    iput p2, p0, Lwt0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lwt0/a;->e:Lvy0/l;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lwt0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Throwable;

    .line 7
    .line 8
    iget-object p0, p0, Lwt0/a;->e:Lvy0/l;

    .line 9
    .line 10
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_0
    check-cast p1, Lzt0/c;

    .line 17
    .line 18
    const-string v0, "it"

    .line 19
    .line 20
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lwt0/a;->e:Lvy0/l;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
