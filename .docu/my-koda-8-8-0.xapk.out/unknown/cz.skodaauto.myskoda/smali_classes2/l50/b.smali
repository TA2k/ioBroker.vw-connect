.class public final Ll50/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Ll50/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ll50/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ll50/b;->d:Ll50/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Lbl0/n;

    .line 2
    .line 3
    const-string p0, "$this$mapData"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p1, Lbl0/n;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v3, p1, Lbl0/n;->c:Lbl0/a;

    .line 11
    .line 12
    iget-object v4, p1, Lbl0/n;->d:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v5, p1, Lbl0/n;->e:Lxj0/f;

    .line 15
    .line 16
    iget-object v6, p1, Lbl0/n;->f:Loo0/b;

    .line 17
    .line 18
    iget-object v7, p1, Lbl0/n;->g:Ljava/lang/String;

    .line 19
    .line 20
    const-string p0, "id"

    .line 21
    .line 22
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string p0, "formattedAddress"

    .line 26
    .line 27
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Lbl0/n;

    .line 31
    .line 32
    const-string v2, ""

    .line 33
    .line 34
    invoke-direct/range {v0 .. v7}, Lbl0/n;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Loo0/b;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object v0
.end method
