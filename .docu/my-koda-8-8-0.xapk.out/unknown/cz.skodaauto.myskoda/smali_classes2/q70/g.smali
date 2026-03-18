.class public final Lq70/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lq70/c;

.field public final b:Lq70/h;


# direct methods
.method public constructor <init>(Lq70/c;Lq70/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq70/g;->a:Lq70/c;

    .line 5
    .line 6
    iput-object p2, p0, Lq70/g;->b:Lq70/h;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lq70/g;->a:Lq70/c;

    .line 2
    .line 3
    check-cast v0, Lo70/a;

    .line 4
    .line 5
    iput-object p1, v0, Lo70/a;->a:Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lq70/g;->b:Lq70/h;

    .line 8
    .line 9
    check-cast p0, Liy/b;

    .line 10
    .line 11
    new-instance v0, Lul0/c;

    .line 12
    .line 13
    sget-object v1, Lly/b;->X3:Lly/b;

    .line 14
    .line 15
    const/4 v4, 0x0

    .line 16
    const/16 v5, 0x3c

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ljava/lang/String;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lq70/g;->a(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
