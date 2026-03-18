.class public final synthetic Lbz/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/UnaryOperator;


# instance fields
.field public final synthetic a:Laz/c;


# direct methods
.method public synthetic constructor <init>(Laz/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbz/a;->a:Laz/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Lbz/c;

    .line 2
    .line 3
    const-string v0, "it"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p1, Lbz/c;->c:Laz/c;

    .line 9
    .line 10
    iget-object p0, p0, Lbz/a;->a:Laz/c;

    .line 11
    .line 12
    if-ne v0, p0, :cond_0

    .line 13
    .line 14
    iget-boolean p0, p1, Lbz/c;->d:Z

    .line 15
    .line 16
    xor-int/lit8 p0, p0, 0x1

    .line 17
    .line 18
    iget v1, p1, Lbz/c;->a:I

    .line 19
    .line 20
    iget-object p1, p1, Lbz/c;->b:Ljava/lang/String;

    .line 21
    .line 22
    const-string v2, "label"

    .line 23
    .line 24
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const-string v2, "interest"

    .line 28
    .line 29
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    new-instance v2, Lbz/c;

    .line 33
    .line 34
    invoke-direct {v2, v1, p1, v0, p0}, Lbz/c;-><init>(ILjava/lang/String;Laz/c;Z)V

    .line 35
    .line 36
    .line 37
    return-object v2

    .line 38
    :cond_0
    return-object p1
.end method
