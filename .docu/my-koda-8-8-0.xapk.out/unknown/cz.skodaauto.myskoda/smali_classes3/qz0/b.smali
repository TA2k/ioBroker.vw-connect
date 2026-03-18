.class public final Lqz0/b;
.super Lqz0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/util/List;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 4

    const-string v0, "serialName"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    .line 4
    const-string v1, "\' is required for type with serial name \'"

    const-string v2, "\', but it was missing"

    .line 5
    const-string v3, "Field \'"

    invoke-static {v3, p1, v1, p2, v2}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const/4 p2, 0x0

    .line 6
    invoke-direct {p0, v0, p1, p2}, Lqz0/b;-><init>(Ljava/util/List;Ljava/lang/String;Lqz0/b;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Ljava/lang/String;Lqz0/b;)V
    .locals 1

    const-string v0, "missingFields"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0, p2, p3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 2
    iput-object p1, p0, Lqz0/b;->d:Ljava/util/List;

    return-void
.end method
