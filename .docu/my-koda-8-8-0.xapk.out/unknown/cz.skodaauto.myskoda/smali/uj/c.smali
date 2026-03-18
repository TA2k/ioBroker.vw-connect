.class public final Luj/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfd/a;


# static fields
.field public static final a:Luj/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Luj/c;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luj/c;->a:Luj/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final i(Lfd/d;Lb6/f;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0xa2bc2c5

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x30

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/16 v0, 0x20

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/16 v0, 0x10

    .line 23
    .line 24
    :goto_0
    or-int/2addr v0, p4

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move v0, p4

    .line 27
    :goto_1
    and-int/lit8 v1, v0, 0x13

    .line 28
    .line 29
    const/16 v2, 0x12

    .line 30
    .line 31
    if-eq v1, v2, :cond_2

    .line 32
    .line 33
    const/4 v1, 0x1

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    const/4 v1, 0x0

    .line 36
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 37
    .line 38
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_3

    .line 43
    .line 44
    and-int/lit8 v0, v0, 0x7e

    .line 45
    .line 46
    invoke-static {p1, p2, p3, v0}, Lzj/a;->a(Lfd/d;Lb6/f;Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 51
    .line 52
    .line 53
    :goto_3
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 54
    .line 55
    .line 56
    move-result-object p3

    .line 57
    if-eqz p3, :cond_4

    .line 58
    .line 59
    new-instance v0, Lph/a;

    .line 60
    .line 61
    const/16 v2, 0xe

    .line 62
    .line 63
    move-object v3, p0

    .line 64
    move-object v4, p1

    .line 65
    move-object v5, p2

    .line 66
    move v1, p4

    .line 67
    invoke-direct/range {v0 .. v5}, Lph/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 71
    .line 72
    :cond_4
    return-void
.end method
