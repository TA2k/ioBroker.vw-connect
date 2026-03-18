.class public final Lz4/d;
.super Ldy0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final synthetic e:Lz4/e;


# direct methods
.method public constructor <init>(Lz4/e;FLjava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lz4/d;->e:Lz4/e;

    .line 2
    .line 3
    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-direct {p0, p1}, Ldy0/a;-><init>(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iput-object p3, p0, Lz4/d;->d:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final afterChange(Lhy0/z;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Ljava/lang/Number;

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 4
    .line 5
    .line 6
    check-cast p3, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    invoke-static {p2}, Ljava/lang/Float;->isNaN(F)Z

    .line 13
    .line 14
    .line 15
    move-result p3

    .line 16
    if-nez p3, :cond_1

    .line 17
    .line 18
    iget-object p3, p0, Lz4/d;->e:Lz4/e;

    .line 19
    .line 20
    iget-object p3, p3, Lz4/e;->b:Ld5/f;

    .line 21
    .line 22
    iget-object p0, p0, Lz4/d;->d:Ljava/lang/String;

    .line 23
    .line 24
    if-nez p0, :cond_0

    .line 25
    .line 26
    invoke-interface {p1}, Lhy0/c;->getName()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    :cond_0
    new-instance p1, Ld5/e;

    .line 31
    .line 32
    invoke-direct {p1, p2}, Ld5/e;-><init>(F)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p3, p0, p1}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    return-void
.end method
