.class public final synthetic Lvh/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvh/y;


# direct methods
.method public synthetic constructor <init>(Lvh/y;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvh/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvh/h;->e:Lvh/y;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lvh/h;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lvh/h;->e:Lvh/y;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Lvh/q;->a:Lvh/q;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lvh/y;->b(Lvh/t;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    iget-object p0, p0, Lvh/y;->e:Lyy0/c2;

    .line 17
    .line 18
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    move-object v1, v0

    .line 23
    check-cast v1, Lvh/w;

    .line 24
    .line 25
    const/4 v7, 0x0

    .line 26
    const/16 v8, 0x6f

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    const/4 v3, 0x0

    .line 30
    const/4 v4, 0x0

    .line 31
    const/4 v5, 0x0

    .line 32
    const/4 v6, 0x0

    .line 33
    invoke-static/range {v1 .. v8}, Lvh/w;->a(Lvh/w;IZZZLvh/v;Lvh/u;I)Lvh/w;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_0

    .line 42
    .line 43
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
