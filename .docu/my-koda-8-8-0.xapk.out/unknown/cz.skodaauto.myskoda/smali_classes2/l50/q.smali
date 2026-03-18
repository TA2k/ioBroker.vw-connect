.class public final Ll50/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ll50/k;

.field public final b:Ll50/i0;


# direct methods
.method public constructor <init>(Ll50/k;Ll50/i0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/q;->a:Ll50/k;

    .line 5
    .line 6
    iput-object p2, p0, Ll50/q;->b:Ll50/i0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Ll50/q;->b:Ll50/i0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Ll50/i0;->a(Lmk0/a;)Ljava/lang/Boolean;

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Ll50/q;->a:Ll50/k;

    .line 8
    .line 9
    check-cast p0, Liy/b;

    .line 10
    .line 11
    sget-object v0, Lly/b;->S1:Lly/b;

    .line 12
    .line 13
    invoke-interface {p0, v0}, Ltl0/a;->a(Lul0/f;)V

    .line 14
    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method
