.class public final Lx41/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/lang/String;Lx41/f;)Lx41/j;
    .locals 2

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lx41/j;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, p1, v1}, Lx41/j;-><init>(Ljava/lang/String;Lx41/f;Lx41/f;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method


# virtual methods
.method public final serializer()Lqz0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    sget-object p0, Lx41/h;->a:Lx41/h;

    .line 2
    .line 3
    return-object p0
.end method
