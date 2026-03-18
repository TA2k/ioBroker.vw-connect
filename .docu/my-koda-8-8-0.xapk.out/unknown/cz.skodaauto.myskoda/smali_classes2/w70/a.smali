.class public final Lw70/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbq0/h;


# direct methods
.method public constructor <init>(Lbq0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/a;->a:Lbq0/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object p0, p0, Lw70/a;->a:Lbq0/h;

    .line 2
    .line 3
    check-cast p0, Lzp0/c;

    .line 4
    .line 5
    iget-object p0, p0, Lzp0/c;->p:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lcq0/m;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    iget-object v1, v0, Lcq0/m;->c:Lcq0/g;

    .line 16
    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 21
    .line 22
    iget-object v3, v1, Lcq0/g;->b:Lcq0/c;

    .line 23
    .line 24
    iget-object v4, v1, Lcq0/g;->c:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v1, v1, Lcq0/g;->d:Ljava/lang/String;

    .line 27
    .line 28
    new-instance v5, Lcq0/g;

    .line 29
    .line 30
    invoke-direct {v5, v2, v3, v4, v1}, Lcq0/g;-><init>(Ljava/lang/Boolean;Lcq0/c;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const/16 v1, 0xb

    .line 34
    .line 35
    const/4 v2, 0x0

    .line 36
    invoke-static {v0, v2, v5, v1}, Lcq0/m;->a(Lcq0/m;Lcq0/n;Lcq0/g;I)Lcq0/m;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {p0, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    :cond_1
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0
.end method
