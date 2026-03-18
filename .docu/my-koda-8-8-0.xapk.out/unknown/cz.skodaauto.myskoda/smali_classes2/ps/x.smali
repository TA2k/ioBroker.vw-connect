.class public final Lps/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Lps/x;

.field public static final b:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lps/x;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lps/x;->a:Lps/x;

    .line 7
    .line 8
    const-string v0, "assignments"

    .line 9
    .line 10
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lps/x;->b:Lzs/c;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Lps/i2;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    check-cast p1, Lps/g1;

    .line 6
    .line 7
    iget-object p0, p1, Lps/g1;->a:Ljava/util/List;

    .line 8
    .line 9
    sget-object p1, Lps/x;->b:Lzs/c;

    .line 10
    .line 11
    invoke-interface {p2, p1, p0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 12
    .line 13
    .line 14
    return-void
.end method
