.class public abstract Lnh/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lly0/n;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lly0/n;

    .line 2
    .line 3
    const-string v1, "^[A-Z]+-[A-Z\\d]{8}-[A-Z\\d]{4}-[A-Z\\d]+$"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lnh/w;->a:Lly0/n;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lyy0/c2;)V
    .locals 10

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    move-object v1, v0

    .line 11
    check-cast v1, Lnh/v;

    .line 12
    .line 13
    const/4 v7, 0x0

    .line 14
    const/16 v9, 0x3b4

    .line 15
    .line 16
    const-string v2, ""

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    const/4 v4, 0x0

    .line 20
    const/4 v5, 0x0

    .line 21
    const/4 v6, 0x0

    .line 22
    sget-object v8, Lnh/g;->a:Lnh/g;

    .line 23
    .line 24
    invoke-static/range {v1 .. v9}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    return-void
.end method
