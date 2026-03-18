.class public abstract Lmh/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Z


# direct methods
.method public constructor <init>(Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lmh/j;->a:Z

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public varargs a([Llx0/l;)V
    .locals 2

    .line 1
    const-string v0, "contextData"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean p0, p0, Lmh/j;->a:Z

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    sget-object p0, Ls41/b;->a:Lpw0/a;

    .line 11
    .line 12
    new-instance p0, Ls41/a;

    .line 13
    .line 14
    array-length v1, p1

    .line 15
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    check-cast p1, [Llx0/l;

    .line 20
    .line 21
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    array-length v1, p1

    .line 25
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    check-cast p1, [Llx0/l;

    .line 30
    .line 31
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    sget-object v0, Ls41/c;->d:Ls41/c;

    .line 35
    .line 36
    array-length v1, p1

    .line 37
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    check-cast p1, [Llx0/l;

    .line 42
    .line 43
    const-string v1, "CAT-AppointmentBooking-UserSendBookRequest"

    .line 44
    .line 45
    invoke-direct {p0, v1, v0, p1}, Leb/j0;-><init>(Ljava/lang/String;Ls41/c;[Llx0/l;)V

    .line 46
    .line 47
    .line 48
    invoke-static {p0}, Ls41/b;->a(Leb/j0;)V

    .line 49
    .line 50
    .line 51
    :cond_0
    return-void
.end method
