.class public final synthetic Le1/g1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Lgy0/e;

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(FLgy0/e;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Le1/g1;->d:F

    .line 5
    .line 6
    iput-object p2, p0, Le1/g1;->e:Lgy0/e;

    .line 7
    .line 8
    iput p3, p0, Le1/g1;->f:I

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Ld4/l;

    .line 2
    .line 3
    new-instance v0, Ld4/h;

    .line 4
    .line 5
    iget v1, p0, Le1/g1;->d:F

    .line 6
    .line 7
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iget-object v2, p0, Le1/g1;->e:Lgy0/e;

    .line 12
    .line 13
    invoke-static {v1, v2}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Ljava/lang/Number;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    iget p0, p0, Le1/g1;->f:I

    .line 24
    .line 25
    invoke-direct {v0, v1, v2, p0}, Ld4/h;-><init>(FLgy0/e;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {p1, v0}, Ld4/x;->h(Ld4/l;Ld4/h;)V

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method
