.class public final Lcz0/l;
.super Lvy0/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lcz0/l;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcz0/l;

    .line 2
    .line 3
    invoke-direct {v0}, Lvy0/x;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcz0/l;->e:Lcz0/l;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final T(Lpx0/g;Ljava/lang/Runnable;)V
    .locals 1

    .line 1
    sget-object p0, Lcz0/e;->f:Lcz0/e;

    .line 2
    .line 3
    const/4 p1, 0x1

    .line 4
    iget-object p0, p0, Lcz0/h;->e:Lcz0/c;

    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p0, p2, p1, v0}, Lcz0/c;->b(Ljava/lang/Runnable;ZZ)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final U(Lpx0/g;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    sget-object p0, Lcz0/e;->f:Lcz0/e;

    .line 2
    .line 3
    const/4 p1, 0x1

    .line 4
    iget-object p0, p0, Lcz0/h;->e:Lcz0/c;

    .line 5
    .line 6
    invoke-virtual {p0, p2, p1, p1}, Lcz0/c;->b(Ljava/lang/Runnable;ZZ)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final W(I)Lvy0/x;
    .locals 1

    .line 1
    invoke-static {p1}, Laz0/b;->a(I)V

    .line 2
    .line 3
    .line 4
    sget v0, Lcz0/k;->d:I

    .line 5
    .line 6
    if-lt p1, v0, :cond_0

    .line 7
    .line 8
    return-object p0

    .line 9
    :cond_0
    invoke-super {p0, p1}, Lvy0/x;->W(I)Lvy0/x;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "Dispatchers.IO"

    .line 2
    .line 3
    return-object p0
.end method
