.class public final Lvv/q;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lt2/b;

.field public final synthetic h:Ljava/util/List;

.field public final synthetic i:I


# direct methods
.method public constructor <init>(ILt2/b;Ljava/util/List;I)V
    .locals 0

    .line 1
    iput p1, p0, Lvv/q;->f:I

    .line 2
    .line 3
    iput-object p2, p0, Lvv/q;->g:Lt2/b;

    .line 4
    .line 5
    iput-object p3, p0, Lvv/q;->h:Ljava/util/List;

    .line 6
    .line 7
    iput p4, p0, Lvv/q;->i:I

    .line 8
    .line 9
    const/4 p1, 0x3

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Lvv/m0;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p3

    .line 11
    const-string v0, "$this$BasicRichText"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    and-int/lit8 v0, p3, 0xe

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    move-object v0, p2

    .line 21
    check-cast v0, Ll2/t;

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr p3, v0

    .line 33
    :cond_1
    and-int/lit8 p3, p3, 0x5b

    .line 34
    .line 35
    const/16 v0, 0x12

    .line 36
    .line 37
    if-ne p3, v0, :cond_3

    .line 38
    .line 39
    move-object p3, p2

    .line 40
    check-cast p3, Ll2/t;

    .line 41
    .line 42
    invoke-virtual {p3}, Ll2/t;->A()Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-nez v0, :cond_2

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 50
    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_3
    :goto_1
    sget-object p3, Lvv/x;->f:Ll2/e0;

    .line 54
    .line 55
    iget v0, p0, Lvv/q;->f:I

    .line 56
    .line 57
    add-int/lit8 v0, v0, 0x1

    .line 58
    .line 59
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    invoke-virtual {p3, v0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 64
    .line 65
    .line 66
    move-result-object p3

    .line 67
    new-instance v0, Lsv/c;

    .line 68
    .line 69
    iget-object v1, p0, Lvv/q;->h:Ljava/util/List;

    .line 70
    .line 71
    iget v2, p0, Lvv/q;->i:I

    .line 72
    .line 73
    iget-object p0, p0, Lvv/q;->g:Lt2/b;

    .line 74
    .line 75
    invoke-direct {v0, p0, p1, v1, v2}, Lsv/c;-><init>(Lt2/b;Lvv/m0;Ljava/util/List;I)V

    .line 76
    .line 77
    .line 78
    const p0, 0x5ddc28e4

    .line 79
    .line 80
    .line 81
    invoke-static {p0, p2, v0}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    const/16 p1, 0x38

    .line 86
    .line 87
    invoke-static {p3, p0, p2, p1}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 88
    .line 89
    .line 90
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    return-object p0
.end method
